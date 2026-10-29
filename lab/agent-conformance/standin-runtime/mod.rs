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
//! `protected_write` is the one store. Plaintext sits in `protected_objects`.
//! `object_revision` is the one digest. A journal under `.AppData/Agents/`
//! stays until the caller presents `create_only` or that current revision.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const LIVE_SCOPE: &str = "all_sessions_live";
const RESIDENT_WORLD: &str = "resident-capsule";
const FAILED_KEEP_SECS: u64 = 60;

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
}

struct Instance {
    id: String,
    name: String,
    start: Start,
    phase: ResidentStatus,
    cause: String,
    ended_at: Option<u64>,
    principal: Option<String>,
}

struct AuditEvent {
    kind: String,
    request_id: String,
}

pub struct StandIn {
    grants: Vec<Grant>,
    admitted: Vec<Admitted>,
    instances: Vec<Instance>,
    next_id: u64,
    instant: u64,
    protected_objects: BTreeMap<String, Vec<u8>>,
    audit: Vec<AuditEvent>,
}

impl StandIn {
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
            admitted: Vec::new(),
            instances: Vec::new(),
            next_id: 1,
            instant: 0,
            protected_objects: BTreeMap::new(),
            audit: Vec::new(),
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
    /// `Ok(())` means the grant authorises that caller. This method reads no
    /// clock, no disk and no WIT file.
    pub fn authorise(&self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        let Some(grant) = self
            .grants
            .iter()
            .find(|grant| grant.request_id == request_id)
        else {
            return Err(unknown_grant(request_id));
        };
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        Ok(())
    }

    /// The one hostcall. A protected `Users` or `UsersAI` invoke stores or reads.
    ///
    /// The response text carries no principal and no resolved root.
    pub fn bridge_envelope(&mut self, line: &str, capsule_id: &str) -> Result<String, String> {
        let envelope: Value =
            serde_json::from_str(line.trim()).map_err(|_| "invalid json".to_owned())?;
        let id = envelope
            .get("id")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let request = envelope.get("request").cloned().unwrap_or(Value::Null);
        let request_type = request
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if request_type != "resource_invoke" {
            return Ok(bridge_error(id, "denied", "unsupported request").to_string());
        }
        let uri = request
            .get("uri")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let operation = request
            .get("operation")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let token = request
            .get("token")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if !uri.starts_with("localhost://Users/") && !uri.starts_with("localhost://UsersAI/") {
            return Ok(bridge_error(
                id,
                "denied",
                "protected storage needs a Users or UsersAI uri",
            )
            .to_string());
        }
        let result = match operation {
            "write" => {
                let Some(body) = request.get("body").and_then(|value| value.as_str()) else {
                    return Ok(
                        bridge_error(id, protected_code(MISSING_CONTENT), MISSING_CONTENT)
                            .to_string(),
                    );
                };
                self.protected_write(capsule_id, token, uri, body.as_bytes(), &request)
                    .map(|data| json!({ "id": id, "response": { "data": data } }))
            }
            "read" => self
                .protected_read(capsule_id, token, uri)
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map(|text| json!({ "id": id, "response": { "data": text } }))
                        .map_err(|_| "stored bytes are not text".to_owned())
                }),
            _ => Err("unsupported operation".to_owned()),
        };
        match result {
            Ok(value) => Ok(value.to_string()),
            Err(message) => Ok(bridge_error(id, protected_code(&message), &message).to_string()),
        }
    }

    /// The one protected store. Plaintext goes into `protected_objects`.
    pub fn protected_write(
        &mut self,
        capsule_id: &str,
        token: &str,
        uri: &str,
        body: &[u8],
        fields: &Value,
    ) -> Result<Value, String> {
        let principal = self.instance_principal(capsule_id)?.to_owned();
        let resolved = resolve_principal_uri(&principal, uri)?;
        self.authorise_presented(
            Caller::Client {
                session_id: capsule_id,
            },
            token,
            uri,
            "write",
            &resolved,
        )?;
        if let Some((_, message)) = agents_area_refusal(&resolved, "write") {
            return Err(message.to_owned());
        }
        let append = append_flag(fields);
        let precondition = write_precondition(fields)?;
        let journal = in_agents_area(&resolved);
        if journal && append {
            return Err(APPEND_JOURNAL.to_owned());
        }
        if append && precondition.is_some() {
            return Err(APPEND_COMBO.to_owned());
        }
        if journal && precondition.is_none() {
            return Err(REVISION_REQUIRED.to_owned());
        }
        let existing = self.protected_objects.get(&resolved).cloned();
        let bytes = if append {
            match existing.clone() {
                Some(mut prior) => {
                    prior.extend_from_slice(body);
                    prior
                }
                None => body.to_vec(),
            }
        } else {
            body.to_vec()
        };
        match &precondition {
            Some(WritePrecondition::Absent) => {
                if existing.is_some() {
                    return Err(CONFLICT.to_owned());
                }
            }
            Some(WritePrecondition::Revision(expected)) => {
                let Some(prior) = existing.as_ref() else {
                    return Err(CONFLICT.to_owned());
                };
                let current = object_revision(&principal, &resolved, prior);
                if current != *expected {
                    return Err(CONFLICT.to_owned());
                }
            }
            None => {}
        }
        self.protected_objects
            .insert(resolved.clone(), bytes.clone());
        self.record_use(token);
        Ok(json!({
            "stored": true,
            "revision": object_revision(&principal, &resolved, &bytes),
        }))
    }

    /// Returns the stored plaintext after the same grant and area checks.
    pub fn protected_read(
        &mut self,
        capsule_id: &str,
        token: &str,
        uri: &str,
    ) -> Result<Vec<u8>, String> {
        let principal = self.instance_principal(capsule_id)?.to_owned();
        let resolved = resolve_principal_uri(&principal, uri)?;
        self.authorise_presented(
            Caller::Client {
                session_id: capsule_id,
            },
            token,
            uri,
            "read",
            &resolved,
        )?;
        if let Some((_, message)) = agents_area_refusal(&resolved, "read") {
            return Err(message.to_owned());
        }
        self.protected_objects
            .get(&resolved)
            .cloned()
            .ok_or_else(|| "protected object is absent".to_owned())
    }

    /// `GET /api/audit`. A client is refused. Newest first.
    pub fn get_audit(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let events = self
            .audit
            .iter()
            .rev()
            .map(|event| {
                json!({
                    "type": event.kind,
                    "request_id": event.request_id,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({ "events": events }))
    }

    fn authorise_presented(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
        resource: &str,
        action: &str,
        resolved: &str,
    ) -> Result<(), String> {
        self.authorise(caller, request_id)
            .map_err(|(_, message)| message)?;
        let (same, action_ok, spend, spelling) = {
            let grant = self
                .grants
                .iter()
                .find(|grant| grant.request_id == request_id)
                .expect("authorise found this grant");
            let same = resources_match(&grant.resource, resource);
            let action_ok = grant.action == action;
            let spelling = action_ok
                && in_agents_area(&grant.resource)
                && agents_area_refusal(resolved, action).is_some();
            (
                same,
                action_ok,
                same && action_ok && grant.duration == "once",
                spelling,
            )
        };
        if spend {
            if let Some(grant) = self
                .grants
                .iter_mut()
                .find(|grant| grant.request_id == request_id)
            {
                grant.life = Life::Exhausted;
            }
        }
        if (same && action_ok) || spelling {
            return Ok(());
        }
        if !action_ok {
            return Err("wrong action".to_owned());
        }
        Err("wrong resource".to_owned())
    }

    fn instance_principal(&self, capsule_id: &str) -> Result<&str, String> {
        let instance = self
            .instances
            .iter()
            .find(|instance| instance.id == capsule_id)
            .ok_or_else(|| format!("unknown instance: {capsule_id}"))?;
        instance.principal.as_deref().ok_or_else(|| {
            "localhost://Users requires a principal-scoped launch context".to_owned()
        })
    }

    fn record_use(&mut self, request_id: &str) {
        self.audit.push(AuditEvent {
            kind: "capability_use".to_owned(),
            request_id: request_id.to_owned(),
        });
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
        });
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Stores the principal the verified launch supplied for this path.
    pub fn bind_verified_principal(
        &mut self,
        path: &str,
        principal: &str,
    ) -> Result<(), (u16, String)> {
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err(self.not_resident(path));
        };
        if principal.is_empty() {
            return Err((400, "verified principal is empty".to_owned()));
        }
        row.principal = Some(principal.to_owned());
        Ok(())
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
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Replaces the instant used for ended-entry age. This method reads no clock.
    pub fn set_instant(&mut self, secs: u64) {
        self.instant = secs;
    }

    /// `POST /api/capsules`.
    pub fn post_capsules(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let path = launch_path(body)?;
        let (name, start) = self.admitted_start(path)?;
        let id = self.mint_id();
        let phase = ResidentStatus::Starting;
        let principal = self
            .admitted
            .iter()
            .find(|row| row.path == path)
            .and_then(|row| row.principal.clone());
        self.instances.push(Instance {
            id: id.clone(),
            name: name.clone(),
            start,
            phase,
            cause: String::new(),
            ended_at: None,
            principal,
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
        self.instances[index].cause = format!("stopped: {reason}");
        self.instances[index].ended_at = Some(instant);
        self.revoke_live(&session_id);
        Ok(())
    }

    /// Writes `Revoked` on `Live` grants of one session. Other lives stay.
    fn revoke_live(&mut self, session_id: &str) {
        for grant in &mut self.grants {
            if grant.session_id == session_id && is_live(grant.life) {
                grant.life = Life::Revoked;
            }
        }
    }

    fn mint_id(&mut self) -> String {
        let id = format!("component-{}", self.next_id);
        self.next_id += 1;
        id
    }

    fn admitted_start(&self, path: &str) -> Result<(String, Start), (u16, String)> {
        if let Some(row) = self.admitted.iter().find(|row| row.path == path) {
            return Ok((row.name.clone(), row.start.clone()));
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

/// One life test. `keep`, `revoke_live` and `authorise` use it.
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

/// One not-live reason. `delete_capsule` and `finish_start` both use it.
fn not_live(status: ResidentStatus) -> (u16, String) {
    (
        400,
        format!("instance is not live: {}", status_text(status)),
    )
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

const CREATE_ONLY_BOOL: &str = "create_only must be a boolean";
const IF_REVISION_STRING: &str = "if_revision must be a non-empty string";
const BOTH_SET: &str = "create_only and if_revision cannot both be set";
const APPEND_JOURNAL: &str =
    "append is read-then-write; Agent journals are written whole with a revision precondition";
const APPEND_COMBO: &str = "append does not take create_only or if_revision";
const REVISION_REQUIRED: &str = "Agent journal writes need create_only or if_revision";
const CONFLICT: &str = "principal-root object write precondition failed";
const SPELLING: &str = "paths under .AppData/Agents/ must be spelled exactly, with lower-case segments of letters, digits, '.', '_' or '-' that do not end in '.'";
const OPERATION_NOT_ALLOWED: &str = "only read and write are allowed under .AppData/Agents/";
const MISSING_CONTENT: &str = "write request missing content";

enum WritePrecondition {
    Absent,
    Revision(String),
}

/// SHA-256 over the principal id, a zero byte, the resolved uri, a zero byte,
/// and the stored plaintext. The result is a quoted lowercase hex string.
pub fn object_revision(principal_id: &str, object_uri: &str, plaintext: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(principal_id.as_bytes());
    digest.update([0u8]);
    digest.update(object_uri.as_bytes());
    digest.update([0u8]);
    digest.update(plaintext);
    format!("\"{:x}\"", digest.finalize())
}

fn bridge_error(id: u64, code: &str, message: &str) -> Value {
    json!({
        "id": id,
        "response": {
            "type": "error",
            "code": code,
            "message": message,
        }
    })
}

fn protected_code(message: &str) -> &'static str {
    match message {
        CREATE_ONLY_BOOL | IF_REVISION_STRING | BOTH_SET | APPEND_COMBO => "invalid_content",
        SPELLING => "invalid_localhost_path",
        APPEND_JOURNAL => "append_not_allowed",
        REVISION_REQUIRED => "revision_required",
        CONFLICT => "revision_conflict",
        OPERATION_NOT_ALLOWED => "operation_not_allowed",
        _ => "denied",
    }
}

fn principal_digest_prefix(principal: &str) -> String {
    let digest = Sha256::digest(principal.as_bytes());
    format!("{:x}", digest)[..24].to_owned()
}

fn scoped_root(uri: &str, alias: &str, root: &str) -> Option<String> {
    if uri == alias {
        return Some(root.to_owned());
    }
    let prefix = format!("{alias}/");
    uri.strip_prefix(&prefix)
        .map(|rest| format!("{root}/{rest}"))
}

fn resolve_principal_uri(principal: &str, uri: &str) -> Result<String, String> {
    if uri.split('/').any(|segment| segment == "..") {
        return Err("invalid principal-root object path".to_owned());
    }
    let prefix = principal_digest_prefix(principal);
    let users = format!("localhost://Users/{prefix}");
    let usersai = format!("localhost://UsersAI/{prefix}");
    if let Some(scoped) = scoped_root(uri, "localhost://Users/self", &users) {
        return Ok(scoped);
    }
    if uri == users || uri.starts_with(&format!("{users}/")) {
        return Ok(uri.to_owned());
    }
    if uri.starts_with("localhost://Users/") {
        return Err(
            "localhost://Users roots must use Users/self or the active principal root".to_owned(),
        );
    }
    if let Some(scoped) = scoped_root(uri, "localhost://UsersAI/self", &usersai) {
        return Ok(scoped);
    }
    if uri == usersai || uri.starts_with(&format!("{usersai}/")) {
        return Ok(uri.to_owned());
    }
    if uri.starts_with("localhost://UsersAI/") {
        return Err(
            "localhost://UsersAI roots must use UsersAI/self or the active principal root"
                .to_owned(),
        );
    }
    Err("protected storage needs a Users or UsersAI uri".to_owned())
}

fn resources_match(grant: &str, presented: &str) -> bool {
    resource_segments(grant) == resource_segments(presented)
}

fn resource_segments(uri: &str) -> Vec<&str> {
    let rest = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
    rest.split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect()
}

fn in_agents_area(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("localhost://Users/") else {
        return false;
    };
    let named: Vec<&str> = rest
        .split('/')
        .filter(|segment| !matches!(*segment, "" | "."))
        .collect();
    let folds_to = |segment: &str, target: &str| segment.to_uppercase().to_lowercase() == target;
    named.len() >= 3 && folds_to(named[1], ".appdata") && folds_to(named[2], "agents")
}

fn agents_area_refusal(rooted: &str, operation: &str) -> Option<(&'static str, &'static str)> {
    if !in_agents_area(rooted) {
        return None;
    }
    if !matches!(operation, "read" | "write") {
        return Some(("operation_not_allowed", OPERATION_NOT_ALLOWED));
    }
    let segments: Vec<&str> = rooted
        .strip_prefix("localhost://Users/")
        .unwrap_or_default()
        .split('/')
        .collect();
    let segment_ok = |segment: &&str| {
        segment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            && !segment.ends_with('.')
    };
    let exact = segments.len() >= 3
        && !segments.iter().any(|segment| matches!(*segment, "" | "."))
        && segments[1] == ".AppData"
        && segments[2] == "Agents"
        && segments[3..].iter().all(segment_ok);
    if !exact || (operation == "write" && segments.len() < 4) {
        return Some(("invalid_localhost_path", SPELLING));
    }
    None
}

fn append_flag(fields: &Value) -> bool {
    matches!(fields.get("append"), Some(Value::Bool(true)))
}

fn write_precondition(fields: &Value) -> Result<Option<WritePrecondition>, String> {
    let create_only = match fields.get("create_only") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(CREATE_ONLY_BOOL.to_owned()),
    };
    let if_revision = match fields.get("if_revision") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(_) => return Err(IF_REVISION_STRING.to_owned()),
    };
    match (create_only, if_revision) {
        (true, Some(_)) => Err(BOTH_SET.to_owned()),
        (true, None) => Ok(Some(WritePrecondition::Absent)),
        (false, Some(revision)) => Ok(Some(WritePrecondition::Revision(revision))),
        (false, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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

    fn shared_body() -> Value {
        json!({ "path": SHARED_PATH })
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
            (Life::Live, true),
            "the stand-in leaves the seeded grant unchanged"
        );
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

    const JOURNAL: &str = "localhost://Users/self/.AppData/Agents/demo-agent/tasks/task-1/journal";

    fn write_line(uri: &str, body: &str, token: &str, fields: Value) -> String {
        let mut request = json!({
            "type": "resource_invoke",
            "uri": uri,
            "operation": "write",
            "body": body,
            "token": token,
        });
        if let Some(object) = fields.as_object() {
            for (key, value) in object {
                request[key] = value.clone();
            }
        }
        json!({ "id": 1, "request": request }).to_string()
    }

    fn host_text(standin: &mut StandIn, line: &str) -> String {
        standin
            .bridge_envelope(line, "component-1")
            .expect("the stand-in answers the invoke")
    }

    fn host_value(standin: &mut StandIn, line: &str) -> Value {
        let text = host_text(standin, line);
        serde_json::from_str(&text).expect("the stand-in returns json")
    }

    fn assert_refused(value: &Value, code: &str, message: &str, why: &str) {
        assert_eq!(value["response"]["code"], code, "{why}");
        assert_eq!(value["response"]["message"], message, "{why}");
    }

    fn assert_journal_running(standin: &StandIn) {
        let listed = shell_list(standin);
        let entry = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == "component-1");
        let expected = json!({
            "id": "component-1",
            "name": "journal-a",
            "status": "running",
            "session_id": "component-1",
            "cause": "",
        });
        assert_eq!(
            entry,
            Some(&expected),
            "the stand-in leaves the journal instance running"
        );
    }

    #[test]
    fn standin_journal_write_keeps_its_revision() {
        let mut standin = StandIn::new();
        standin
            .admit_resident("/capsules/journal-a", "journal-a", Start::Ok)
            .expect("the stand-in admits journal-a");
        standin
            .bind_verified_principal("/capsules/journal-a", "person:local:ada")
            .expect("the stand-in binds the verified principal");
        let launched = standin
            .post_capsules(Caller::Shell, &json!({ "path": "/capsules/journal-a" }))
            .expect("the stand-in launches journal-a");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in names the first launch component-1"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes start");
        assert_journal_running(&standin);
        let journal = JOURNAL;
        standin.seed_grant(
            "req-j",
            "component-1",
            journal,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-r",
            "component-1",
            journal,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-once",
            "component-1",
            journal,
            "write",
            "once",
            1,
            Life::Live,
            false,
        );
        let notes = "localhost://Users/self/notes";
        standin.seed_grant(
            "req-note",
            "component-1",
            notes,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-note-read",
            "component-1",
            notes,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        let resolved = resolve_principal_uri("person:local:ada", journal)
            .expect("the stand-in resolves the journal");
        let first_line = write_line(
            journal,
            "journal v1",
            "req-j",
            json!({ "create_only": true }),
        );
        let first_text = host_text(&mut standin, &first_line);
        assert!(
            !first_text.contains("person:local:ada"),
            "the stand-in response names no principal"
        );
        assert!(
            !first_text.contains("localhost://"),
            "the stand-in response names no resolved root"
        );
        let first: Value = serde_json::from_str(&first_text).expect("the stand-in returns json");
        let v1 = object_revision("person:local:ada", &resolved, b"journal v1");
        assert_eq!(
            first["response"]["data"]["stored"], true,
            "the stand-in stores the journal"
        );
        assert_eq!(
            first["response"]["data"]["revision"], v1,
            "the stand-in returns the revision of the stored journal"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v1".to_vec(),
            "the stand-in returns the first journal bytes"
        );
        let again = host_value(
            &mut standin,
            &write_line(
                journal,
                "journal v1 again",
                "req-j",
                json!({ "create_only": true }),
            ),
        );
        assert_refused(
            &again,
            "revision_conflict",
            CONFLICT,
            "the stand-in keeps the first journal when create_only finds it",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v1".to_vec(),
            "the stand-in keeps the first journal bytes"
        );
        let blind = host_value(
            &mut standin,
            &write_line(journal, "blind", "req-j", json!({})),
        );
        assert_refused(
            &blind,
            "revision_required",
            REVISION_REQUIRED,
            "the stand-in refuses a blind journal write",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v1".to_vec(),
            "the stand-in keeps the first journal bytes after a blind write"
        );
        assert_eq!(
            grant_record(&standin, "req-j"),
            (Life::Live, false),
            "the stand-in leaves the session grant live"
        );
        let once_blind = host_value(
            &mut standin,
            &write_line(journal, "blind", "req-once", json!({})),
        );
        assert_refused(
            &once_blind,
            "revision_required",
            REVISION_REQUIRED,
            "the stand-in refuses a blind journal write on a once grant",
        );
        assert_eq!(
            grant_record(&standin, "req-once"),
            (Life::Exhausted, false),
            "the stand-in exhausts the once grant when the write stores nothing"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v1".to_vec(),
            "the stand-in keeps the first journal bytes after the once grant"
        );
        let second = host_value(
            &mut standin,
            &write_line(journal, "journal v2", "req-j", json!({ "if_revision": v1 })),
        );
        let v2 = object_revision("person:local:ada", &resolved, b"journal v2");
        assert_eq!(
            second["response"]["data"]["stored"], true,
            "the stand-in stores the revised journal"
        );
        assert_eq!(
            second["response"]["data"]["revision"], v2,
            "the stand-in returns the revision of the revised journal"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in returns the revised journal bytes"
        );
        let stale = host_value(
            &mut standin,
            &write_line(journal, "replayed", "req-j", json!({ "if_revision": v1 })),
        );
        assert_refused(
            &stale,
            "revision_conflict",
            CONFLICT,
            "the stand-in refuses a stale journal revision",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in keeps the revised journal bytes"
        );
        let appended = host_value(
            &mut standin,
            &write_line(
                journal,
                " more",
                "req-j",
                json!({ "append": true, "if_revision": v2 }),
            ),
        );
        assert_refused(
            &appended,
            "append_not_allowed",
            APPEND_JOURNAL,
            "the stand-in refuses an append to the journal",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in keeps the revised journal bytes after an append"
        );
        let both = host_value(
            &mut standin,
            &write_line(
                journal,
                "both",
                "req-j",
                json!({ "create_only": true, "if_revision": v2 }),
            ),
        );
        assert_refused(
            &both,
            "invalid_content",
            BOTH_SET,
            "the stand-in refuses create_only together with if_revision",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in keeps the revised journal bytes when both preconditions are set"
        );
        let dotted = format!("{journal}.");
        let dot = host_value(
            &mut standin,
            &write_line(&dotted, "dot", "req-j", json!({ "create_only": true })),
        );
        assert_eq!(
            dot["response"]["code"], "invalid_localhost_path",
            "the stand-in refuses a journal segment that ends in '.'"
        );
        assert!(
            dot["response"]["message"]
                .as_str()
                .unwrap_or("")
                .starts_with("paths under .AppData/Agents/ must be spelled exactly"),
            "the stand-in names the exact journal spelling: {dot}"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in keeps the revised journal bytes after a bad spelling"
        );
        let notes_resolved = resolve_principal_uri("person:local:ada", notes)
            .expect("the stand-in resolves the note");
        let aa = host_value(
            &mut standin,
            &write_line(notes, "aa", "req-note", json!({})),
        );
        assert_eq!(
            aa["response"]["data"]["stored"], true,
            "the stand-in stores the note"
        );
        assert_eq!(
            aa["response"]["data"]["revision"],
            object_revision("person:local:ada", &notes_resolved, b"aa"),
            "the stand-in returns the revision of the stored note"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-note-read", notes)
                .expect("the stand-in returns the stored note"),
            b"aa".to_vec(),
            "the stand-in returns the stored note"
        );
        let bb = host_value(
            &mut standin,
            &write_line(notes, "bb", "req-note", json!({ "append": true })),
        );
        assert_eq!(
            bb["response"]["data"]["stored"], true,
            "the stand-in appends the note"
        );
        assert_eq!(
            bb["response"]["data"]["revision"],
            object_revision("person:local:ada", &notes_resolved, b"aabb"),
            "the stand-in returns the revision of the appended note"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-note-read", notes)
                .expect("the stand-in returns the stored note"),
            b"aabb".to_vec(),
            "the stand-in returns the appended note"
        );
        let cc = host_value(
            &mut standin,
            &write_line(
                notes,
                "cc",
                "req-note",
                json!({ "append": true, "create_only": true }),
            ),
        );
        assert_refused(
            &cc,
            "invalid_content",
            APPEND_COMBO,
            "the stand-in refuses append together with create_only",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-note-read", notes)
                .expect("the stand-in returns the stored note"),
            b"aabb".to_vec(),
            "the stand-in keeps the appended note"
        );
        let bad_bool = host_value(
            &mut standin,
            &write_line(journal, "no", "req-j", json!({ "create_only": "yes" })),
        );
        assert_refused(
            &bad_bool,
            "invalid_content",
            CREATE_ONLY_BOOL,
            "the stand-in refuses a create_only value that is not a boolean",
        );
        let bad_revision = host_value(
            &mut standin,
            &write_line(journal, "no", "req-j", json!({ "if_revision": "" })),
        );
        assert_refused(
            &bad_revision,
            "invalid_content",
            IF_REVISION_STRING,
            "the stand-in refuses an empty if_revision",
        );
        let bad_type = host_value(
            &mut standin,
            &write_line(journal, "no", "req-j", json!({ "if_revision": 1 })),
        );
        assert_refused(
            &bad_type,
            "invalid_content",
            IF_REVISION_STRING,
            "the stand-in refuses an if_revision value that is not a string",
        );
        let append_text = host_value(
            &mut standin,
            &write_line(journal, "no", "req-j", json!({ "append": "yes" })),
        );
        assert_refused(
            &append_text,
            "revision_required",
            REVISION_REQUIRED,
            "the stand-in treats a non-true append as absent",
        );
        let null_create = host_value(
            &mut standin,
            &write_line(journal, "no", "req-j", json!({ "create_only": null })),
        );
        assert_refused(
            &null_create,
            "revision_required",
            REVISION_REQUIRED,
            "the stand-in treats a null create_only as false",
        );
        let wrong_action = host_value(
            &mut standin,
            &write_line(journal, "no", "req-r", json!({ "create_only": true })),
        );
        assert_refused(
            &wrong_action,
            "denied",
            "wrong action",
            "the stand-in refuses a read grant for a journal write",
        );
        let wrong_resource = host_value(&mut standin, &write_line(notes, "zz", "req-j", json!({})));
        assert_refused(
            &wrong_resource,
            "denied",
            "wrong resource",
            "the stand-in refuses the journal grant for the note",
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-note-read", notes)
                .expect("the stand-in returns the stored note"),
            b"aabb".to_vec(),
            "the stand-in keeps the appended note after a wrong grant"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-r", journal)
                .expect("the stand-in returns the stored journal"),
            b"journal v2".to_vec(),
            "the stand-in keeps the revised journal bytes after a wrong grant"
        );
        let crossed = standin.protected_read("component-1", "req-note", journal);
        assert_eq!(
            crossed.expect_err("the stand-in refuses the notes grant for the journal"),
            "wrong action",
            "the stand-in refuses the notes write grant for a journal read"
        );
        let bare = "localhost://Users/self/.AppData/Agents";
        let bare_write = host_value(
            &mut standin,
            &write_line(bare, "no", "req-j", json!({ "create_only": true })),
        );
        assert_refused(
            &bare_write,
            "invalid_localhost_path",
            SPELLING,
            "the stand-in refuses a journal write with no name under Agents",
        );
        assert_eq!(
            agents_area_refusal(&resolved, "delete"),
            Some(("operation_not_allowed", OPERATION_NOT_ALLOWED)),
            "the stand-in allows only read and write under Agents"
        );
        let client_audit = standin.get_audit(Caller::Client {
            session_id: "component-1",
        });
        assert_eq!(
            client_audit,
            Err((403, "This endpoint requires shell privileges".to_owned())),
            "the stand-in refuses a client audit read"
        );
        let audit = standin
            .get_audit(Caller::Shell)
            .expect("the stand-in returns the shell audit");
        let events = audit["events"]
            .as_array()
            .expect("the stand-in returns audit events");
        assert_eq!(
            events.len(),
            4,
            "the stand-in records one event for each successful store"
        );
        assert!(
            events.iter().all(|event| event["type"] == "capability_use"),
            "the stand-in records capability_use: {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["request_id"] == "req-j")
                .count(),
            2,
            "the stand-in records the first journal store and the revised journal store"
        );
        assert_eq!(
            events[0]["request_id"], "req-note",
            "the stand-in lists the newest store first"
        );
        assert_eq!(events[1]["request_id"], "req-note");
        assert_eq!(events[2]["request_id"], "req-j");
        assert_eq!(events[3]["request_id"], "req-j");
        assert_eq!(
            grant_record(&standin, "req-j"),
            (Life::Live, false),
            "the stand-in leaves the session grant live"
        );
        assert_eq!(
            grant_record(&standin, "req-r"),
            (Life::Live, false),
            "the stand-in leaves the read grant live"
        );
        let usersai = "localhost://UsersAI/self/journal";
        standin.seed_grant(
            "req-ai",
            "component-1",
            usersai,
            "write",
            "session",
            1,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-ai-read",
            "component-1",
            usersai,
            "read",
            "session",
            1,
            Life::Live,
            false,
        );
        let ai_one = host_value(
            &mut standin,
            &write_line(usersai, "one", "req-ai", json!({})),
        );
        assert_eq!(
            ai_one["response"]["data"]["stored"], true,
            "the stand-in stores a UsersAI journal without a precondition"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-ai-read", usersai)
                .expect("the stand-in returns the UsersAI journal"),
            b"one".to_vec(),
            "the stand-in returns the UsersAI journal"
        );
        let ai_two = host_value(
            &mut standin,
            &write_line(usersai, "two", "req-ai", json!({})),
        );
        assert_eq!(
            ai_two["response"]["data"]["stored"], true,
            "the stand-in replaces a UsersAI journal"
        );
        assert_eq!(
            standin
                .protected_read("component-1", "req-ai-read", usersai)
                .expect("the stand-in returns the UsersAI journal"),
            b"two".to_vec(),
            "the stand-in replaces the UsersAI journal bytes"
        );
        assert!(
            !in_agents_area(&resolve_principal_uri("person:local:ada", usersai).expect("resolved")),
            "the stand-in keeps UsersAI outside the Agents rule"
        );
        assert_journal_running(&standin);
    }
}
