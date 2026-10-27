//! Lab stand-in for the Runtime's live-grant view, not the Runtime.
//!
//! `get_capability_list` is the one answer for `GET /api/capability/list`.
//! `None` is the plain route. `Some("all_sessions_live")` is the query form.
//! One filter keeps a grant whose life is `Live`. An ended session stays.
//!
//! `post_capsules` and `get_capsules` answer the capsule routes for an
//! admitted resident guest. Launch answers `starting` with the Bus session
//! before `finish_start`. One map names the five statuses. One check refuses
//! a client on a shell-only route.

use serde_json::{json, Map, Value};

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

/// Five list statuses. This slice stores `Starting`, `Running` and `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidentStatus {
    Starting,
    Running,
    #[allow(dead_code)]
    Stopping,
    #[allow(dead_code)]
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
}

struct Instance {
    id: String,
    name: String,
    start: Start,
    phase: ResidentStatus,
    cause: String,
    failed_at: Option<u64>,
}

pub struct StandIn {
    grants: Vec<Grant>,
    admitted: Vec<Admitted>,
    instances: Vec<Instance>,
    next_id: u64,
    instant: u64,
}

impl StandIn {
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
            admitted: Vec::new(),
            instances: Vec::new(),
            next_id: 1,
            instant: 0,
        }
    }

    /// Lab test seam, not a route.
    ///
    /// `granted_at` is the seeded value. This method reads no clock.
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
        });
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Applies the admitted `Start` once. This is the stand-in's `resident.start`.
    pub fn finish_start(&mut self, id: &str) -> Result<(), (u16, String)> {
        let instant = self.instant;
        let Some(instance) = self.instances.iter_mut().find(|instance| instance.id == id) else {
            return Err((400, format!("unknown instance: {id}")));
        };
        if instance.phase != ResidentStatus::Starting {
            return Err((400, "start already returned".to_owned()));
        }
        let (phase, cause, failed_at) = apply_start(&instance.start, instant);
        instance.phase = phase;
        instance.cause = cause;
        instance.failed_at = failed_at;
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Replaces the instant used for failed-entry age. This method reads no clock.
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
        self.instances.push(Instance {
            id: id.clone(),
            name: name.clone(),
            start,
            phase,
            cause: String::new(),
            failed_at: None,
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
    grant.life == Life::Live && visible(grant, caller)
}

fn visible(grant: &Grant, caller: Caller<'_>) -> bool {
    match caller {
        Caller::Shell => true,
        Caller::Client { session_id } => grant.session_id == session_id,
    }
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

fn keeps_instance(instance: &Instance, instant: u64) -> bool {
    match instance.phase {
        ResidentStatus::Starting | ResidentStatus::Running => true,
        ResidentStatus::Failed => match instance.failed_at {
            Some(at) => instant.saturating_sub(at) < FAILED_KEEP_SECS,
            None => false,
        },
        ResidentStatus::Stopping | ResidentStatus::Stopped => false,
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
                Err((400, reason))
                    if reason.starts_with("unknown instance:") && reason.contains("component-9")
            ),
            "the stand-in refuses an unknown instance: {unknown:?}"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in leaves the running instance in place"
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
}
