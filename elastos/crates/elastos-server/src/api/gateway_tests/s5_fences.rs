//! A5 S5 fence rows: routes 13, 14, 15, 16 and 19.
//!
//! Every route here takes no caller path, URI or object reference. The
//! Runtime builds the location from the launch token's resolved root. Each row
//! names the production line that builds it and shows that two agents'
//! launches get two different locations.
//!
//! Both agents in a row launch through `launch_capsule` first, under the
//! production admission with `dev_mode` false. The route call then carries the
//! token the production issuer (`issue_home_launch_token_for_auth_grant`) mints
//! for that agent's stored record. No production flow mints an app token from
//! an agent launch today, so these rows prove the location rule for two
//! admitted agents, not that the launched Agent Host itself calls the route;
//! `report-round3.md` states that limit.

use super::*;
use serde_json::Value;

use axum::extract::Extension;
use axum::Json as AxumJson;
use elastos_compute::providers::ComponentProvider;
use elastos_runtime::primitives::audit::AuditLog;
use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
use std::sync::Arc;

/// The signed Agent Host both agents are bound to. It declares the agent kind
/// and asks the Runtime for nothing, so a launch ends well with no grant.
const HOST_NAME: &str = "s5-agent-host";
const HOST_REGISTRY_CID: &str = "bafkreis5host";

/// A Home with two stored agents of one owner. Each agent has its own
/// owner-root protection, and both are bound to one signed Agent Host folder
/// this fixture creates, so each can launch through `launch_capsule`. The fixed
/// root the location plants pin to also holds a protection here, so a plant
/// reaches the row's own separate-location assertion instead of stopping at a
/// missing protection.
struct TwoAgentHome {
    dir: tempfile::TempDir,
    agents: [String; 2],
    runtime: Arc<crate::runtime::Runtime>,
    audit_log: Arc<AuditLog>,
    host_dir: std::path::PathBuf,
    launch_grant: String,
}

async fn two_agent_home() -> TwoAgentHome {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let context = local_home_launch_token_context(dir.path()).unwrap();
    let owner = context.principal_id().to_string();
    crate::auth::store_test_principal_root_protection(dir.path(), &owner);
    crate::agents::tests::make_admin(dir.path(), &owner);
    // The plants pin every route's location to this fixed principal and root.
    // Both hold a current protection here, so a planted row reads and writes
    // the shared location and fails on its separate-location assertion.
    crate::auth::valid_agent::plant(dir.path());
    crate::auth::store_test_principal_root_protection_for(
        dir.path(),
        crate::auth::valid_agent::ID,
        crate::auth::valid_agent::ROOT,
    );

    // One signed Agent Host folder that declares the agent kind, from the
    // asks-nothing component: the launch has no bridge call to grant.
    let host_dir = dir.path().join(HOST_NAME);
    std::fs::create_dir_all(&host_dir).unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/components/asks-nothing/bundle");
    for file in ["capsule.json", "asks-nothing.component.wasm"] {
        std::fs::copy(fixture.join(file), host_dir.join(file)).unwrap();
    }
    let key = SigningKey::from_bytes(&[0x44; 32]);
    let wasm = std::fs::read(host_dir.join("asks-nothing.component.wasm")).unwrap();
    let mut manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&std::fs::read(host_dir.join("capsule.json")).unwrap()).unwrap();
    manifest.name = HOST_NAME.to_string();
    manifest.agent = Some(elastos_common::AgentDeclaration {
        kind: elastos_common::AgentKind::Agent,
    });
    sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
    std::fs::write(
        host_dir.join("capsule.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let host_cid = crate::stage_cmd::bundle_cid(&host_dir).expect("the host folder is walkable");

    // The one admission key both the Host's signature and this Runtime trust.
    let storage = Arc::new(
        elastos_storage::providers::LocalFSProvider::new(dir.path().join(".s5-storage"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(crate::runtime::Runtime::with_providers_and_component(
        storage,
        Vec::new(),
        Some(Arc::new(ComponentProvider::new())),
    ));
    runtime
        .configure_capsule_admission(
            dir.path(),
            &[hex::encode(key.verifying_key().to_bytes())],
            false,
        )
        .await
        .unwrap();
    let audit_log = Arc::new(AuditLog::new());

    let record = crate::auth::stored_principal_record(dir.path(), &owner)
        .unwrap()
        .unwrap();
    let caller = crate::agents::Caller {
        principal_id: &owner,
        proof_binding_id: &record.proof_binding_id,
        session_id: "session:s5-fences",
    };
    crate::agents::set_enabled(dir.path(), &caller, true, 1).unwrap();
    let mut agents = Vec::new();
    for name in ["a", "b"] {
        let view = crate::agents::create(
            dir.path(),
            &caller,
            &crate::agents::CreateRequest {
                display_name: name.to_string(),
                agent_host: HOST_NAME.to_string(),
                request_id: format!("request-s5-{name}"),
            },
            |host| {
                Ok(
                    crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                        host,
                        HOST_REGISTRY_CID,
                        &host_cid,
                    ),
                )
            },
            1,
        )
        .unwrap();
        agents.push(view.agent_id);
    }
    let [a, b] = agents.as_slice() else {
        panic!("two agents");
    };
    let launch_grant =
        issue_home_launch_token_with_context(dir.path(), HOST_NAME, &context).unwrap();
    TwoAgentHome {
        dir,
        agents: [a.clone(), b.clone()],
        runtime,
        audit_log,
        host_dir,
        launch_grant,
    }
}

/// One agent's launch through the production route. Admission binds the stored
/// agent's own id and root; the component starts and ends well.
async fn launch_agent(home: &TwoAgentHome, agent: &str) {
    let request: crate::api::routes::LaunchRequest = serde_json::from_value(json!({
        "path": home.host_dir.to_string_lossy(),
        "launch_grant": home.launch_grant,
        "agent_id": agent,
    }))
    .unwrap();
    let _ = crate::api::routes::launch_capsule(
        Extension(home.runtime.clone()),
        Extension(home.audit_log.clone()),
        Extension(Some(home.dir.path().to_path_buf())),
        AxumJson(request),
    )
    .await
    .expect("the stored agent's launch is admitted and starts");
}

/// A Home launch token for one agent, minted by the production issuer from a
/// session grant the production store holds. No production flow mints an
/// agent's grant today: the stored agent's own proof binding is the subject.
fn agent_token(home: &TwoAgentHome, app: &str, agent: &str) -> String {
    let record = crate::auth::stored_principal_record(home.dir.path(), agent)
        .unwrap()
        .unwrap();
    let now = unix_now();
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:s5:{}", uuid_like_token()),
        session_id: format!("auth:s5:{}", uuid_like_token()),
        principal_id: agent.to_string(),
        proof_binding_id: record.proof_binding_id.clone(),
        issued_at: now,
        expires_at: now + 3600,
        apps: vec![app.to_string()],
    };
    crate::auth::store_session_grant(home.dir.path(), grant.clone()).unwrap();
    issue_home_launch_token_for_auth_grant(home.dir.path(), app, &grant).unwrap()
}

fn root_of(home: &TwoAgentHome, agent: &str) -> String {
    crate::auth::principal_stored_localhost_root(Some(home.dir.path()), agent).unwrap()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn object_path(home: &TwoAgentHome, root: &str, relative: &str) -> std::path::PathBuf {
    elastos_common::localhost::rooted_localhost_fs_path(
        home.dir.path(),
        &format!("{root}/{relative}"),
    )
    .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn app_request(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    let builder = test_browser_request("localhost:61180", "null")
        .method(method)
        .uri(uri)
        .header("x-elastos-home-token", token);
    match body {
        Some(body) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Route 13, and row 9. The location is
/// `gateway_home_agent.rs:79-84 home_agent_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/HomeAgent/workspace.json`
/// from the token's resolved root. Two admitted agents get two different
/// locations, and one never reads the other's document.
#[tokio::test]
async fn route_13_home_agent_workspace_keeps_two_admitted_agents_locations_apart() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
    launch_agent(&home, a).await;
    launch_agent(&home, b).await;
    let token_a = agent_token(&home, "home-agent", a);
    let token_b = agent_token(&home, "home-agent", b);
    let (root_a, root_b) = (root_of(&home, a), root_of(&home, b));
    let relative = ".AppData/ElastOS/HomeAgent/workspace.json";
    let path_a = object_path(&home, &root_a, relative);
    let path_b = object_path(&home, &root_b, relative);
    assert_ne!(path_a, path_b, "two launches, two locations");

    let write = |token: String, marker: &'static str| {
        app_request(
            "PUT",
            "/api/apps/home-agent/workspace",
            &token,
            Some(json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {"marker": marker}
            })),
        )
    };
    let put_a = app
        .clone()
        .oneshot(write(token_a.clone(), "a"))
        .await
        .unwrap();
    assert_eq!(put_a.status(), StatusCode::OK);

    // The row's own separate-location assertion: B's launch reads its own
    // empty workspace, never A's document.
    let get_b = app
        .clone()
        .oneshot(app_request(
            "GET",
            "/api/apps/home-agent/workspace",
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(get_b.status(), StatusCode::OK);
    let seen_by_b = response_json(get_b).await;
    assert_eq!(
        seen_by_b["revision"], 0,
        "B's launch reads its own empty workspace"
    );
    assert_eq!(
        seen_by_b["document"],
        json!({}),
        "B's launch reads its own empty workspace"
    );

    let seen_by_a = response_json(
        app.clone()
            .oneshot(app_request(
                "GET",
                "/api/apps/home-agent/workspace",
                &token_a,
                None,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        seen_by_a["document"],
        json!({"marker": "a"}),
        "A's launch reads its own document"
    );

    // No request field can name another location.
    let named = app
        .clone()
        .oneshot(app_request(
            "PUT",
            "/api/apps/home-agent/workspace",
            &token_b,
            Some(json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {},
                "path": format!("{root_a}/{relative}")
            })),
        ))
        .await
        .unwrap();
    assert!(
        named.status().is_client_error(),
        "a caller path is refused: {}",
        named.status()
    );
    assert!(!path_b.exists());

    let put_b = app.oneshot(write(token_b, "b")).await.unwrap();
    assert_eq!(put_b.status(), StatusCode::OK);
    assert!(path_a.is_file(), "A's write landed under A's root");
    assert!(path_b.is_file(), "B's write landed under B's own root");
}

/// Route 14. The location is `gateway_assistant.rs:134-139
/// assistant_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace.json`.
/// Two admitted agents get two different locations.
#[tokio::test]
async fn route_14_assistant_workspace_keeps_two_admitted_agents_locations_apart() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
    launch_agent(&home, a).await;
    launch_agent(&home, b).await;
    let token_a = agent_token(&home, "assistant", a);
    let token_b = agent_token(&home, "assistant", b);
    let (root_a, root_b) = (root_of(&home, a), root_of(&home, b));
    let relative = ".AppData/ElastOS/Assistant/workspace.json";
    let path_a = object_path(&home, &root_a, relative);
    let path_b = object_path(&home, &root_b, relative);
    assert_ne!(path_a, path_b, "two launches, two locations");

    let write = |token: String, draft: &'static str| {
        app_request(
            "PUT",
            "/api/apps/assistant/workspace",
            &token,
            Some(json!({
                "schema": "elastos.assistant.workspace/v1",
                "if_revision": 0,
                "sessions": [],
                "draft": draft
            })),
        )
    };
    assert_eq!(
        app.clone()
            .oneshot(write(token_a.clone(), "a"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The row's own separate-location assertion: B's launch reads its own
    // empty workspace, never A's draft.
    let seen_by_b = app
        .clone()
        .oneshot(app_request(
            "GET",
            "/api/apps/assistant/workspace",
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(seen_by_b.status(), StatusCode::OK);
    assert_eq!(
        response_json(seen_by_b).await,
        json!({
            "schema": "elastos.assistant.workspace/v1",
            "revision": 0,
            "sessions": [],
            "draft": ""
        }),
        "B's launch reads its own empty workspace"
    );

    assert_eq!(
        app.clone()
            .oneshot(write(token_b.clone(), "b"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let seen_by_a = response_json(
        app.oneshot(app_request(
            "GET",
            "/api/apps/assistant/workspace",
            &token_a,
            None,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(seen_by_a["draft"], "a", "A's launch reads its own draft");
    assert!(path_a.is_file());
    assert!(path_b.is_file());
}

/// Route 15. The location is
/// `gateway_assistant_workspace_v2.rs:96-106 object_location`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace-v2.json`.
/// Two admitted agents get two different locations.
#[tokio::test]
async fn route_15_assistant_workspace_v2_keeps_two_admitted_agents_locations_apart() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
    launch_agent(&home, a).await;
    launch_agent(&home, b).await;
    let token_a = agent_token(&home, "assistant", a);
    let token_b = agent_token(&home, "assistant", b);
    let (root_a, root_b) = (root_of(&home, a), root_of(&home, b));
    let relative = ".AppData/ElastOS/Assistant/workspace-v2.json";
    let path_a = object_path(&home, &root_a, relative);
    let path_b = object_path(&home, &root_b, relative);
    assert_ne!(path_a, path_b, "two launches, two locations");

    // The first v2 save names the retained sources it read, as the client's
    // own GET returns them.
    let read_first =
        |token: String| app_request("GET", "/api/apps/assistant/workspace-v2", &token, None);
    let seen_a = app
        .clone()
        .oneshot(read_first(token_a.clone()))
        .await
        .unwrap();
    assert_eq!(seen_a.status(), StatusCode::OK);
    let seen_a = response_json(seen_a).await;
    assert_eq!(seen_a["revision"], 0);
    assert_eq!(seen_a["document"], json!({}));
    let migration_a = seen_a["migration_revision"]
        .as_str()
        .expect("the first save names its retained sources")
        .to_string();

    let write = |token: String, marker: &'static str, migration_revision: String| {
        app_request(
            "PUT",
            "/api/apps/assistant/workspace-v2",
            &token,
            Some(json!({
                "schema": "elastos.assistant.workspace/v2",
                "if_revision": 0,
                "document": {"marker": marker},
                "migration_revision": migration_revision
            })),
        )
    };
    assert_eq!(
        app.clone()
            .oneshot(write(token_a, "a", migration_a))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The row's own separate-location assertion: B's launch reads its own
    // empty document, never A's.
    let seen = app
        .clone()
        .oneshot(read_first(token_b.clone()))
        .await
        .unwrap();
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = response_json(seen).await;
    assert_eq!(
        seen["revision"], 0,
        "B's launch reads its own empty workspace"
    );
    assert_eq!(
        seen["document"],
        json!({}),
        "B's launch reads its own empty workspace"
    );
    let migration_b = seen["migration_revision"]
        .as_str()
        .expect("the first save names its retained sources")
        .to_string();

    assert_eq!(
        app.oneshot(write(token_b, "b", migration_b))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(path_a.is_file());
    assert!(path_b.is_file());
}

/// Route 16. The location is `gateway_home_system.rs:6818-6820
/// home_browser_localhost_root` read by `:7033-7038 home_browser_state_uri`,
/// which builds `{context.root().localhost_root()}/.AppData/ElastOS/Home/browser-state.json`.
/// Two admitted agents get two different locations.
#[tokio::test]
async fn route_16_home_state_keeps_two_admitted_agents_locations_apart() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
    launch_agent(&home, a).await;
    launch_agent(&home, b).await;
    let token_a = agent_token(&home, "home", a);
    let token_b = agent_token(&home, "home", b);
    let (root_a, root_b) = (root_of(&home, a), root_of(&home, b));
    let relative = ".AppData/ElastOS/Home/browser-state.json";
    let path_a = object_path(&home, &root_a, relative);
    let path_b = object_path(&home, &root_b, relative);
    assert_ne!(path_a, path_b, "two launches, two locations");

    // The Home capsule needs the destination origin, exactly.
    let request = |method: &str, token: &str, body: Option<Value>| {
        let builder = test_browser_request("localhost:61180", "http://localhost:61180")
            .method(method)
            .uri("/api/apps/home/state")
            .header("x-elastos-home-token", token);
        match body {
            Some(body) => builder
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    };

    // The row's own separate-location assertion: each launch's state is under
    // its own root.
    let seen_a = app
        .clone()
        .oneshot(request("GET", &token_a, None))
        .await
        .unwrap();
    assert_eq!(seen_a.status(), StatusCode::OK);
    assert_eq!(
        response_json(seen_a).await["localhost_root"],
        root_a,
        "each launch's state is under its own root"
    );

    let seen_b = app
        .clone()
        .oneshot(request("GET", &token_b, None))
        .await
        .unwrap();
    assert_eq!(seen_b.status(), StatusCode::OK);
    assert_eq!(
        response_json(seen_b).await["localhost_root"],
        root_b,
        "each launch's state is under its own root"
    );

    let written = app
        .clone()
        .oneshot(request(
            "POST",
            &token_a,
            Some(json!({"layout": {"columns": 3}})),
        ))
        .await
        .unwrap();
    assert_eq!(written.status(), StatusCode::OK);
    assert!(path_a.is_file());
    assert!(!path_b.exists());

    let seen_b = app.oneshot(request("GET", &token_b, None)).await.unwrap();
    assert_eq!(seen_b.status(), StatusCode::OK);
    assert_eq!(
        response_json(seen_b).await["layout"],
        Value::Null,
        "B's launch reads its own state"
    );
}
