//! A saved connection-v1 offer, approved through the Inbox route.
#![cfg(unix)]

use axum::body::Body;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use serde_json::json;
use tower::ServiceExt as _;

use super::{
    app_token_for_authority, clear_hosted_ai_validate_doubles, gateway_router,
    install_openrouter_models_double, install_venice_validate_double, passkey_authority,
    test_browser_request, test_state, OpenRouterModelsDouble, VeniceAuthDouble, INBOX_CAPSULE_ID,
};

async fn post_json(
    app: &axum::Router,
    uri: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri(uri)
                .header("x-elastos-home-token", token)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn install_doubles() {
    install_openrouter_models_double(OpenRouterModelsDouble::Models(vec![
        "fixture/model".to_string()
    ]));
    install_venice_validate_double(
        VeniceAuthDouble::Permitted,
        Some(vec![(
            "fixture/model".to_string(),
            Some("private".to_string()),
        )]),
    );
}

fn offer_id(payload: &serde_json::Value) -> String {
    payload["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["provider"] == "openrouter")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn inbox(app: &axum::Router, token: &str, action: &str) -> (StatusCode, String) {
    post_json(
        app,
        "/api/apps/inbox/actions",
        token,
        json!({ "action_id": action }),
    )
    .await
}

/// Saved through the system route and approved through the Inbox route.
/// The charge is accepted. After the approval ends, and after the owner's
/// passkey is revoked, the next charge is refused before the file moves.
#[tokio::test]
async fn a_connection_v1_offer_is_charged_only_while_the_approval_stands() {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            clear_hosted_ai_validate_doubles();
        }
    }
    let _clear = Clear;
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    crate::api::seed_model_provider_operator_offers_for_test(
        dir.path(),
        vec![json!({
            "id": "model:local-llama",
            "adapter": { "kind": "local_llama_cpp_text" }
        })],
    )
    .unwrap();
    install_doubles();
    let (status, body) = post_json(
        &app,
        "/api/apps/system/ai-provider",
        &authority.system_token,
        json!({
            "provider": "openrouter",
            "name": "Jev",
            "api_key": "sk-or-fixture-valid",
            "model": "fixture/model"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    let offer_id = offer_id(&payload);
    let token = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &authority);
    let first = crate::api::model_provider_egress_decision::stage_broker_connection_request(
        dir.path(),
        &offer_id,
    )
    .unwrap();
    let (status, body) = inbox(&app, &token, &format!("model-egress-approve:{first}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The broker matches the connection, not this scope's configuration.
    let path = dir
        .path()
        .join("providers")
        .join("model-provider")
        .join("egress-decisions.json");
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["decisions"][0]["scope"]["configuration_id"] = serde_json::json!("ab".repeat(32));
    crate::auth::atomic_write(&path, &serde_json::to_vec(&file).unwrap()).unwrap();
    let agent = crate::agents::tests::plant_for_dispatch(
        dir.path(),
        &authority.principal_id,
        &authority.principal_id,
    );
    let owner = &authority.principal_id;
    crate::agents::charge_model_spend(dir.path(), owner, &agent, (0, 0), 1, 64, Some(&offer_id))
        .unwrap();
    let spent = crate::agents::model_spend(dir.path(), &agent).unwrap().1;
    assert!(spent > 0, "{spent}");
    let (status, body) = inbox(&app, &token, &format!("model-egress-end:{first}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ended = crate::agents::charge_model_spend(
        dir.path(),
        owner,
        &agent,
        (0, 0),
        1,
        64,
        Some(&offer_id),
    );
    assert!(
        matches!(ended, Err(crate::agents::SpendRefusal::HostedRun)),
        "{ended:?}"
    );
    assert_eq!(
        crate::agents::model_spend(dir.path(), &agent).unwrap().1,
        spent
    );
    let second = crate::api::model_provider_egress_decision::stage_broker_connection_request(
        dir.path(),
        &offer_id,
    )
    .unwrap();
    let (status, body) = inbox(&app, &token, &format!("model-egress-approve:{second}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    crate::agents::charge_model_spend(dir.path(), owner, &agent, (0, 0), 1, 64, Some(&offer_id))
        .unwrap();
    let again = crate::agents::model_spend(dir.path(), &agent).unwrap().1;
    assert!(again > spent, "{again} {spent}");
    crate::auth::revoke_passkey_binding(
        dir.path(),
        &authority.proof_binding_id,
        crate::auth::now_ts(),
    )
    .unwrap();
    let revoked = crate::agents::charge_model_spend(
        dir.path(),
        owner,
        &agent,
        (0, 0),
        1,
        64,
        Some(&offer_id),
    );
    assert!(
        matches!(revoked, Err(crate::agents::SpendRefusal::HostedRun)),
        "{revoked:?}"
    );
    assert_eq!(
        crate::agents::model_spend(dir.path(), &agent).unwrap().1,
        again
    );
}
