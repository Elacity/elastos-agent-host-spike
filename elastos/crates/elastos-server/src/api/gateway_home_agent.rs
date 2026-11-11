use super::*;
use serde_json::Value;
use std::sync::{Mutex, OnceLock};

pub(super) const HOME_AGENT_WORKSPACE_MAX_BYTES: usize = 1024 * 1024;

const HOME_AGENT_CAPSULE_ID: &str = "home-agent";
const HOME_AGENT_WORKSPACE_SCHEMA: &str = "elastos.home-agent.workspace/v1";
const HOME_AGENT_WORKSPACE_RELATIVE_ROOT: &str = ".AppData/ElastOS/HomeAgent";
const HOME_AGENT_WORKSPACE_FILE: &str = "workspace.json";
const HOME_AGENT_WORKSPACE_MAX_DEPTH: usize = 24;

/// The Home Agent's workspace: the capsule owns the document's shape, the
/// Runtime owns where it lives, who may read it, its size and its revision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct HomeAgentWorkspace {
    schema: String,
    revision: u64,
    document: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HomeAgentWorkspacePutRequest {
    schema: String,
    if_revision: u64,
    document: Value,
}

pub(super) async fn home_agent_workspace_get(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let context =
        match require_home_launch_token_context(&state.data_dir, &headers, HOME_AGENT_CAPSULE_ID) {
            Ok(context) => context,
            Err(err) => return super::home_error_response(err),
        };
    match load_home_agent_workspace(&state.data_dir, &context) {
        Ok(workspace) => Json(workspace).into_response(),
        Err(err) => super::home_error_response(err),
    }
}

pub(super) async fn home_agent_workspace_put(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<HomeAgentWorkspacePutRequest>,
) -> Response {
    let context =
        match require_home_launch_token_context(&state.data_dir, &headers, HOME_AGENT_CAPSULE_ID) {
            Ok(context) => context,
            Err(err) => return super::home_error_response(err),
        };
    if let Err(err) = validate_workspace_put_request(&request) {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    match save_home_agent_workspace(&state.data_dir, &context, request) {
        Ok(workspace) => Json(workspace).into_response(),
        Err(err) if is_revision_conflict(&err) => {
            (StatusCode::CONFLICT, err.to_string()).into_response()
        }
        Err(err) => gateway_assistant_workspace_v2::migration_error_response(&err)
            .unwrap_or_else(|| super::home_error_response(err)),
    }
}

pub(super) fn principal_root_protected_object_inventory(
    localhost_root: &str,
) -> Vec<crate::auth::PrincipalRootProtectedObjectDeclarationV1> {
    vec![
        crate::auth::PrincipalRootProtectedObjectDeclarationV1::root(format!(
            "{localhost_root}/{HOME_AGENT_WORKSPACE_RELATIVE_ROOT}"
        )),
    ]
}

fn home_agent_workspace_uri(context: &HomeLaunchTokenContext) -> String {
    format!(
        "{}/{HOME_AGENT_WORKSPACE_RELATIVE_ROOT}/{HOME_AGENT_WORKSPACE_FILE}",
        context.root().localhost_root()
    )
}

fn home_agent_workspace_path(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<PathBuf> {
    rooted_localhost_fs_path(data_dir, &home_agent_workspace_uri(context))
        .ok_or_else(|| anyhow::anyhow!("invalid Home Agent workspace root"))
}

fn default_home_agent_workspace() -> HomeAgentWorkspace {
    HomeAgentWorkspace {
        schema: HOME_AGENT_WORKSPACE_SCHEMA.to_string(),
        revision: 0,
        document: Value::Object(serde_json::Map::new()),
    }
}

fn load_home_agent_workspace(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<HomeAgentWorkspace> {
    let path = home_agent_workspace_path(data_dir, context)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(default_home_agent_workspace());
        }
        Err(err) => return Err(err.into()),
    }
    let bytes = crate::auth::read_principal_root_object_resolved(
        data_dir,
        context.root(),
        &home_agent_workspace_uri(context),
        &path,
    )?;
    validate_workspace_bytes(&bytes)?;
    let workspace: HomeAgentWorkspace = serde_json::from_slice(&bytes)?;
    validate_workspace(&workspace)?;
    Ok(workspace)
}

fn save_home_agent_workspace(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    request: HomeAgentWorkspacePutRequest,
) -> anyhow::Result<HomeAgentWorkspace> {
    let _migration_guard = gateway_assistant_workspace_v2::mutation_guard()?;
    gateway_assistant_workspace_v2::ensure_legacy_writable(data_dir, context)?;
    let _guard = home_agent_workspace_mutation_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("home agent workspace mutation lock poisoned"))?;
    let current = load_home_agent_workspace(data_dir, context)?;
    if request.if_revision != current.revision {
        anyhow::bail!("home agent workspace revision conflict");
    }
    let next = HomeAgentWorkspace {
        schema: request.schema,
        revision: current
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("home agent workspace revision overflow"))?,
        document: request.document,
    };
    validate_workspace(&next)?;
    let bytes = serde_json::to_vec_pretty(&next)?;
    validate_workspace_bytes(&bytes)?;
    let path = home_agent_workspace_path(data_dir, context)?;
    crate::auth::write_protected_principal_root_object_resolved(
        data_dir,
        context.root(),
        &home_agent_workspace_uri(context),
        &path,
        &bytes,
    )?;
    Ok(next)
}

fn validate_workspace_put_request(request: &HomeAgentWorkspacePutRequest) -> anyhow::Result<()> {
    validate_workspace(&HomeAgentWorkspace {
        schema: request.schema.clone(),
        revision: request.if_revision,
        document: request.document.clone(),
    })
}

fn validate_workspace(workspace: &HomeAgentWorkspace) -> anyhow::Result<()> {
    if workspace.schema != HOME_AGENT_WORKSPACE_SCHEMA {
        anyhow::bail!("home agent workspace schema must be {HOME_AGENT_WORKSPACE_SCHEMA}");
    }
    if !workspace.document.is_object() {
        anyhow::bail!("home agent workspace document must be a JSON object");
    }
    if json_depth(&workspace.document) > HOME_AGENT_WORKSPACE_MAX_DEPTH {
        anyhow::bail!(
            "home agent workspace document exceeds depth {}",
            HOME_AGENT_WORKSPACE_MAX_DEPTH
        );
    }
    Ok(())
}

fn validate_workspace_bytes(bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.len() > HOME_AGENT_WORKSPACE_MAX_BYTES {
        anyhow::bail!(
            "home agent workspace exceeds {} bytes",
            HOME_AGENT_WORKSPACE_MAX_BYTES
        );
    }
    Ok(())
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn is_revision_conflict(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string() == "home agent workspace revision conflict")
}

fn home_agent_workspace_mutation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(super) fn validate_legacy_workspace_bytes(bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
    validate_workspace_bytes(bytes)?;
    let workspace = serde_json::from_slice(bytes)?;
    validate_workspace(&workspace)?;
    Ok(serde_json::from_slice(bytes)?)
}

#[cfg(test)]
mod r3_tests {
    use super::super::r3_stored_root_tests::{
        fixture, seed, verified_parent_device_context, HUMAN_ROOT, NEEDS_PROTECTION,
    };
    use super::*;

    #[test]
    fn agent_uri_uses_stored_root() {
        let (_dir, context) = fixture(true);
        assert_eq!(
            home_agent_workspace_uri(&context),
            format!(
                "{}/.AppData/ElastOS/HomeAgent/workspace.json",
                super::super::r3_stored_root_tests::AGENT_ROOT
            ),
            "R3 home_agent URI uses UsersAI"
        );
    }

    #[test]
    fn agent_read_uses_stored_root() {
        let (dir, context) = fixture(true);
        seed(dir.path(), ".AppData/ElastOS/HomeAgent/workspace.json",
            br#"{"schema":"elastos.home-agent.workspace/v1","revision":7,"document":{"draft":"agent draft"}}"#);
        let result = load_home_agent_workspace(dir.path(), &context)
            .map(|workspace| workspace.revision)
            .map_err(|err| err.to_string());
        assert_eq!(result, Ok(7), "R3 home_agent read uses UsersAI");
    }

    #[test]
    fn agent_write_uses_stored_root() {
        let (dir, context) = fixture(true);
        let request = serde_json::from_value(serde_json::json!({
            "schema": "elastos.home-agent.workspace/v1", "if_revision": 0,
            "document":{"draft":"agent draft"}
        }))
        .unwrap();
        let result = save_home_agent_workspace(dir.path(), &context, request);
        let writes = crate::auth::principal_object_io::writes(dir.path());
        assert!(
            writes.iter().any(|path| path.ends_with(
                "UsersAI/ba287e12925d9408db0f24e3/.AppData/ElastOS/HomeAgent/workspace.json"
            )),
            "R3 home_agent write records the stored-root object: {writes:?}"
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            NEEDS_PROTECTION,
            "R3 home_agent write reaches UsersAI protection gate"
        );
    }

    #[test]
    fn human_keeps_workspace_round_trip() {
        let (dir, context) = fixture(false);
        assert_eq!(
            home_agent_workspace_uri(&context),
            format!("{HUMAN_ROOT}/.AppData/ElastOS/HomeAgent/workspace.json")
        );
        assert_eq!(
            load_home_agent_workspace(dir.path(), &context)
                .unwrap()
                .revision,
            0
        );
        let request = serde_json::from_value(serde_json::json!({
            "schema": "elastos.home-agent.workspace/v1", "if_revision": 0,
            "document":{"draft":"human draft"}
        }))
        .unwrap();
        let saved = save_home_agent_workspace(dir.path(), &context, request).unwrap();
        assert_eq!(saved.revision, 1);
        assert_eq!(
            load_home_agent_workspace(dir.path(), &context).unwrap(),
            saved
        );
    }

    #[test]
    fn parent_signed_workspace_reads_parent_root_and_keeps_protection_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (context, parent_root, child_root, token) =
            verified_parent_device_context(dir.path(), "home-agent");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-elastos-home-token", token.parse().unwrap());
        let route_error =
            require_home_launch_token_context(dir.path(), &headers, "home-agent").unwrap_err();
        assert!(
            route_error.to_string().contains("Signer DID mismatch"),
            "{route_error}"
        );
        let uri = home_agent_workspace_uri(&context);
        assert_eq!(
            uri,
            format!("{parent_root}/.AppData/ElastOS/HomeAgent/workspace.json")
        );
        let path = home_agent_workspace_path(dir.path(), &context).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, br#"{"schema":"elastos.home-agent.workspace/v1","revision":7,"document":{"draft":"parent"}}"#).unwrap();
        let child_uri = format!("{child_root}/.AppData/ElastOS/HomeAgent/workspace.json");
        let child_path =
            elastos_common::localhost::rooted_localhost_fs_path(dir.path(), &child_uri).unwrap();
        std::fs::create_dir_all(child_path.parent().unwrap()).unwrap();
        std::fs::write(&child_path, br#"{"schema":"elastos.home-agent.workspace/v1","revision":99,"document":{"draft":"child decoy"}}"#).unwrap();
        assert_eq!(
            load_home_agent_workspace(dir.path(), &context)
                .map(|workspace| workspace.revision)
                .map_err(|error| error.to_string()),
            Ok(7)
        );
        let request = serde_json::from_value(serde_json::json!({
            "schema": "elastos.home-agent.workspace/v1", "if_revision": 7,
            "document": {"draft": "replacement"}
        }))
        .unwrap();
        assert_eq!(
            save_home_agent_workspace(dir.path(), &context, request)
                .unwrap_err()
                .to_string(),
            NEEDS_PROTECTION,
        );
        assert!(std::fs::read(&path)
            .unwrap()
            .windows(6)
            .any(|bytes| bytes == b"parent"));
        assert!(!crate::auth::principal_object_io::reads(dir.path()).contains(&child_path));
        std::fs::remove_file(&child_path).unwrap();
        std::fs::remove_file(&path).unwrap();
        crate::auth::create_owner_only_dir_all(dir.path(), path.parent().unwrap()).unwrap();
        crate::auth::store_test_principal_root_protection_for(
            dir.path(),
            context.principal_id(),
            &parent_root,
        );
        let request = serde_json::from_value(serde_json::json!({
            "schema": "elastos.home-agent.workspace/v1", "if_revision": 0,
            "document": {"draft": "protected parent"}
        }))
        .unwrap();
        let saved = save_home_agent_workspace(dir.path(), &context, request);
        assert!(saved.is_ok(), "parent workspace save: {saved:?}");
        assert_eq!(
            load_home_agent_workspace(dir.path(), &context)
                .unwrap()
                .revision,
            1
        );
        assert!(!child_path.exists());
        assert!(!crate::auth::principal_object_io::writes(dir.path()).contains(&child_path));
    }
}

/// R8d evidence row for the Home Agent workspace, for a parent passkey person
/// on a child Runtime. Entry: `save_home_agent_workspace` (line 126), which
/// `home_agent_workspace_put` calls after the token is verified.
#[cfg(test)]
mod r8d_passkey_rows {
    use super::super::gateway_tests::r8d_passkey_rows::{
        passkey_person, refusal, PasskeyPerson,
    };
    use super::super::r3_stored_root_tests::NEEDS_PROTECTION;
    use super::*;

    fn put_request() -> HomeAgentWorkspacePutRequest {
        serde_json::from_value(serde_json::json!({
            "schema": HOME_AGENT_WORKSPACE_SCHEMA,
            "if_revision": 0,
            "document": {"draft": "r8d child draft"}
        }))
        .unwrap()
    }

    /// Today the child's save is refused with the protection text and leaves
    /// no file.
    #[tokio::test(flavor = "current_thread")]
    async fn r8d_child_home_agent_workspace_save_for_the_passkey_person() {
        let person: PasskeyPerson = passkey_person(HOME_AGENT_CAPSULE_ID);
        let child = person.child.path();
        let saved = save_home_agent_workspace(child, &person.ctx, put_request());
        assert_eq!(refusal(saved).as_deref(), Some(NEEDS_PROTECTION));
        // The route gives the same text with the status it answers.
        let answer = home_agent_workspace_put(
            State(person.child_state()),
            person.route_headers(HOME_AGENT_CAPSULE_ID),
            Json(put_request()),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&body), NEEDS_PROTECTION);
        person.assert_child_holds_only(&[]);
    }
}
