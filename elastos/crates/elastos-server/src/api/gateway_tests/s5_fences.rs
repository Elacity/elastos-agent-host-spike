//! A5 S5 fence rows: routes 13, 14, 15, 16 and 19.
//!
//! Every route here takes no caller path, URI or object reference. The
//! Runtime builds the location from the launch token's resolved root. Each row
//! names the production line that builds it and shows that two agents'
//! launches (two sessions for route 19) get two different locations.

use super::*;
use serde_json::Value;

/// A Home with two stored agents of one owner. Each agent has its own
/// owner-root protection, so the protected workspace routes can read and
/// write its fixed object.
struct TwoAgentHome {
    dir: tempfile::TempDir,
    agents: [String; 2],
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
                agent_host: "agent-host".to_string(),
                request_id: format!("request-s5-{name}"),
            },
            |host| {
                Ok(
                    crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                        host,
                        "bafkreis5fences",
                        "bafkreis5fencesbytes",
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
    TwoAgentHome {
        dir,
        agents: [a.clone(), b.clone()],
    }
}

/// A Home launch token for one agent's launch, bound to `app`, with the active
/// session grant verification needs.
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
/// `{context.root().localhost_root()}/.AppData/ElastOS/HomeAgent/workspace.json`.
/// Two agents' launches get two different locations, and one never reads the
/// other's document.
#[tokio::test]
async fn route_13_home_agent_workspace_builds_one_location_per_agents_launch() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
    let token_a = agent_token(&home, "home-agent", a);
    let token_b = agent_token(&home, "home-agent", b);
    let (root_a, root_b) = (root_of(&home, a), root_of(&home, b));
    let relative = ".AppData/ElastOS/HomeAgent/workspace.json";
    let path_a = object_path(&home, &root_a, relative);
    let path_b = object_path(&home, &root_b, relative);
    assert_ne!(path_a, path_b, "two launches, two locations");

    let put_a = app
        .clone()
        .oneshot(app_request(
            "PUT",
            "/api/apps/home-agent/workspace",
            &token_a,
            Some(json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {"marker": "a"}
            })),
        ))
        .await
        .unwrap();
    assert_eq!(put_a.status(), StatusCode::OK);
    assert!(
        path_a.is_file(),
        "A's write landed where its own root puts it"
    );
    assert!(!path_b.exists(), "A's write did not land under B's root");

    // B's launch reads its own empty workspace, never A's document.
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
    assert_eq!(seen_by_b["revision"], 0);
    assert_eq!(seen_by_b["document"], json!({}));

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

    let put_b = app
        .oneshot(app_request(
            "PUT",
            "/api/apps/home-agent/workspace",
            &token_b,
            Some(json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {"marker": "b"}
            })),
        ))
        .await
        .unwrap();
    assert_eq!(put_b.status(), StatusCode::OK);
    assert!(path_b.is_file(), "B's write landed under B's own root");
}

/// Route 14. The location is `gateway_assistant.rs:134-139
/// assistant_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace.json`.
/// Two agents' launches get two different locations.
#[tokio::test]
async fn route_14_assistant_workspace_builds_one_location_per_agents_launch() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
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
            .oneshot(write(token_a, "a"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(path_a.is_file());
    assert!(!path_b.exists());

    let seen = app
        .clone()
        .oneshot(app_request(
            "GET",
            "/api/apps/assistant/workspace",
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        response_json(seen).await,
        json!({
            "schema": "elastos.assistant.workspace/v1",
            "revision": 0,
            "sessions": [],
            "draft": ""
        })
    );

    assert_eq!(
        app.oneshot(write(token_b, "b")).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(path_b.is_file());
}

/// Route 15. The location is
/// `gateway_assistant_workspace_v2.rs:96-106 object_location`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace-v2.json`.
/// Two agents' launches get two different locations.
#[tokio::test]
async fn route_15_assistant_workspace_v2_builds_one_location_per_agents_launch() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
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
    assert!(path_a.is_file());
    assert!(!path_b.exists());

    let seen = app
        .clone()
        .oneshot(read_first(token_b.clone()))
        .await
        .unwrap();
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = response_json(seen).await;
    assert_eq!(seen["revision"], 0);
    assert_eq!(seen["document"], json!({}));
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
    assert!(path_b.is_file());
}

/// Route 16. The location is `gateway_home_system.rs:6818-6820
/// home_browser_localhost_root` read by `:7033-7038 home_browser_state_uri`,
/// which builds `{context.root().localhost_root()}/.AppData/ElastOS/Home/browser-state.json`.
/// Two agents' launches get two different locations.
#[tokio::test]
async fn route_16_home_state_builds_one_location_per_agents_launch() {
    if crate::agents::require_build().is_err() {
        return;
    }
    let home = two_agent_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let [a, b] = &home.agents;
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

    let seen_a = app
        .clone()
        .oneshot(request("GET", &token_a, None))
        .await
        .unwrap();
    assert_eq!(seen_a.status(), StatusCode::OK);
    assert_eq!(response_json(seen_a).await["localhost_root"], root_a);

    let seen_b = app
        .clone()
        .oneshot(request("GET", &token_b, None))
        .await
        .unwrap();
    assert_eq!(seen_b.status(), StatusCode::OK);
    assert_eq!(response_json(seen_b).await["localhost_root"], root_b);

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
