use super::*;

async fn unstored_principal_is_refused(app: &str, endpoint: &str, body: Value) {
    use elastos_runtime::auth::AuthSessionGrantV1;
    let dir = tempfile::tempdir().unwrap();
    let now = now_ts();
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.into(),
        grant_id: "grant:r3".into(),
        session_id: "session:r3".into(),
        principal_id: "person:local:r3-missing".into(),
        proof_binding_id: "proof:r3".into(),
        issued_at: now,
        expires_at: now + 600,
        apps: vec![app.into()],
    };
    crate::auth::store_session_grant(dir.path(), grant.clone()).unwrap();
    let context = HomeLaunchTokenContext::for_test(
        grant.principal_id,
        grant.session_id,
        Some(grant.proof_binding_id),
        grant.grant_id,
    );
    // The signed token and active grant reach root resolution before any handler.
    let token = issue_home_launch_token_with_context(dir.path(), app, &context).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("host", "localhost:61180".parse().unwrap());
    headers.insert("origin", "null".parse().unwrap());
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    let err = require_home_launch_token_context(dir.path(), &headers, app).unwrap_err();
    assert_eq!(err.to_string(), "Home launch principal root unresolved");
    for method in ["GET", "PUT"] {
        let request = test_browser_request("localhost:61180", "null")
            .method(method)
            .uri(endpoint)
            .header("x-elastos-home-token", &token)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = gateway_router(test_state(dir.path()))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {endpoint}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &bytes[..],
            b"Gateway request requires an admitted host and caller",
            "{method} {endpoint}"
        );
    }
}

#[tokio::test]
async fn assistant_refuses_unstored_principal() {
    unstored_principal_is_refused(
        "assistant",
        "/api/apps/assistant/workspace",
        json!({"schema":"elastos.assistant.workspace/v1", "if_revision":0, "draft":""}),
    )
    .await;
}

#[tokio::test]
async fn workspace_v2_refuses_unstored_principal() {
    unstored_principal_is_refused(
        "assistant",
        "/api/apps/assistant/workspace-v2",
        json!({"schema":"elastos.assistant.workspace/v2", "if_revision":0, "document":{}}),
    )
    .await;
}

#[tokio::test]
async fn home_agent_refuses_unstored_principal() {
    unstored_principal_is_refused(
        "home-agent",
        "/api/apps/home-agent/workspace",
        json!({"schema":"elastos.home-agent.workspace/v1", "if_revision":0, "document":{}}),
    )
    .await;
}
