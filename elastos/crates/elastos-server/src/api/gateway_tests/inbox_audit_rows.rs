use super::*;

/// Gives the fixture an acting session that differs from its principal, and
/// stores the grant the launch-token verifier matches.
fn acting_authority_with_distinct_session(
    dir: &std::path::Path,
    name: &str,
) -> TestPasskeyAuthority {
    let mut authority = passkey_authority_with_name(dir, Some(name));
    let acting_session = format!("auth:{}", uuid_like_token());
    crate::auth::store_session_grant(
        dir,
        AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: authority.grant_id.clone(),
            session_id: acting_session.clone(),
            principal_id: authority.principal_id.clone(),
            proof_binding_id: authority.proof_binding_id.clone(),
            issued_at: crate::auth::now_ts(),
            expires_at: crate::auth::now_ts() + 12 * 60 * 60,
            apps: vec![INBOX_CAPSULE_ID.to_string()],
        },
    )
    .unwrap();
    authority.session_id = acting_session;
    assert_ne!(authority.principal_id, authority.session_id);
    authority
}

/// Admits host and caller exactly as the passing Inbox action rows do: the
/// Inbox handler verifies the launch binding from these headers.
async fn post_inbox_action(
    state: GatewayState,
    token: &str,
    action_id: &str,
) -> (StatusCode, String) {
    let request = test_browser_request("localhost:61180", "null")
        .method("POST")
        .uri("/api/apps/inbox/actions")
        .header("x-elastos-home-token", token)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "action_id": action_id }).to_string()))
        .unwrap();
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let response = inbox_action(State(state), parts.headers, body).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn inbox_wallet_approval_reject_audits_acting_principal_and_session() {
    let dir = tempfile::tempdir().unwrap();
    let authority = acting_authority_with_distinct_session(dir.path(), "Alice");
    let token = launch_token_for_authority_context(dir.path(), INBOX_CAPSULE_ID, &authority);
    let provider = MockWalletProvider {
        approvals: TokioMutex::new(vec![json!({
            "request_id": "wallet-approval:test",
            "status": "pending",
            "principal_id": authority.principal_id.clone(),
        })]),
        ..Default::default()
    };
    let state = wallet_test_state_with_provider(dir.path(), provider).await;
    let (status, body) =
        post_inbox_action(state, &token, "wallet-reject-request:wallet-approval:test").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let event = crate::auth::load_auth_state(dir.path())
        .unwrap()
        .audit
        .into_iter()
        .find(|event| {
            event.event_type == "wallet.approval.rejected"
                && event.challenge_id.as_deref() == Some("wallet-approval:test")
        })
        .expect("wallet approval rejection audit event");
    assert_eq!(
        event.principal_id.as_deref(),
        Some(authority.principal_id.as_str())
    );
    assert_eq!(
        event.session_id.as_deref(),
        Some(authority.session_id.as_str())
    );
}

#[tokio::test]
async fn inbox_wallet_price_deny_audits_acting_principal_and_session() {
    let dir = tempfile::tempdir().unwrap();
    let authority = acting_authority_with_distinct_session(dir.path(), "Alice");
    let token = launch_token_for_authority_context(dir.path(), INBOX_CAPSULE_ID, &authority);
    let state = wallet_test_state(dir.path()).await;
    let (status, body) = post_inbox_action(state, &token, "wallet-price-http-deny:coingecko").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let event = crate::auth::load_auth_state(dir.path())
        .unwrap()
        .audit
        .into_iter()
        .find(|event| {
            event.event_type == "wallet.price_source.policy"
                && event.result == "rejected"
                && event.challenge_id.as_deref() == Some(WALLET_PRICE_HTTP_REQUEST_ID)
        })
        .expect("wallet price denial audit event");
    assert_eq!(
        event.principal_id.as_deref(),
        Some(authority.principal_id.as_str())
    );
    assert_eq!(
        event.session_id.as_deref(),
        Some(authority.session_id.as_str())
    );
}
