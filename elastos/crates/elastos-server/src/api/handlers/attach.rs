//! Attach endpoint — exchanges a local secret for a short-lived session token.
//!
//! Callers read the `attach_secret` from the chmod-600 runtime-coords.json file,
//! then POST it here to receive a bearer token.  This keeps long-lived secrets
//! off the wire and out of persistent storage.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use elastos_runtime::session::{SessionRegistry, SessionType};

/// How many attach shells this process remembers. The next note drops the oldest.
pub(crate) const ATTACH_SHELL_CAP: usize = 8;

type NotedShells = (
    std::collections::VecDeque<String>,
    std::collections::VecDeque<String>,
);

/// Shell tokens minted by attach with the secret. A shell created another way
/// is not in this set. A validate miss drops the token. The cap names the one it drops.
#[derive(Clone, Default)]
pub struct AttachShells {
    inner: Arc<std::sync::Mutex<NotedShells>>,
}

impl AttachShells {
    #[rustfmt::skip]
    pub fn note(&self, token: &str) {
        let Ok(mut set) = self.inner.lock() else { return };
        set.1.retain(|old| old != token);
        if set.0.iter().any(|kept| kept == token) { return }
        if set.0.len() >= ATTACH_SHELL_CAP {
            if let Some(old) = set.0.pop_front() {
                if set.1.len() >= ATTACH_SHELL_CAP { set.1.pop_front(); }
                set.1.push_back(old);
            }
        }
        set.0.push_back(token.to_string());
    }

    pub fn holds(&self, token: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|set| set.0.iter().any(|kept| kept == token))
    }

    pub fn evicted(&self, token: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|set| set.1.iter().any(|old| old == token))
    }

    #[rustfmt::skip]
    pub fn forget(&self, token: &str) {
        let Ok(mut set) = self.inner.lock() else { return };
        set.0.retain(|kept| kept != token);
        set.1.retain(|old| old != token);
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|set| set.0.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Shared state for the attach endpoint.
#[derive(Clone)]
pub struct AttachState {
    pub session_registry: Arc<SessionRegistry>,
    /// The expected secret (from runtime-coords.json).
    pub secret: String,
    pub shells: AttachShells,
}

#[derive(serde::Deserialize)]
pub struct AttachRequest {
    /// The attach secret from runtime-coords.json.
    pub secret: String,
    /// Requested scope: "shell" or "client" (default: "client").
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "client".into()
}

#[derive(serde::Serialize)]
pub struct AttachResponse {
    pub token: String,
    pub session_type: String,
}

/// POST /api/auth/attach
///
/// Validates the attach secret and returns a short-lived session token.
/// The secret is local-only (localhost, chmod 600 file) so timing attacks
/// are not a realistic threat; we use a simple equality check.
pub async fn attach(
    State(state): State<AttachState>,
    Json(body): Json<AttachRequest>,
) -> impl IntoResponse {
    if body.secret != state.secret {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invalid attach secret"})),
        )
            .into_response();
    }

    let session_type = match body.scope.as_str() {
        "shell" => SessionType::Shell,
        _ => SessionType::Capsule,
    };

    let session = state
        .session_registry
        .create_session(session_type, None)
        .await;
    if session.is_shell() {
        state.shells.note(&session.token);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!(AttachResponse {
            token: session.token,
            session_type: session.session_type.to_string(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use elastos_runtime::primitives::audit::AuditLog;
    use tower::ServiceExt;

    fn test_router(secret: &str) -> Router {
        let state = AttachState {
            session_registry: Arc::new(SessionRegistry::new(Arc::new(AuditLog::new()))),
            secret: secret.to_string(),
            shells: AttachShells::default(),
        };
        Router::new()
            .route("/api/auth/attach", post(attach))
            .with_state(state)
    }

    #[tokio::test]
    async fn attach_returns_token_for_valid_secret() {
        let app = test_router("test-secret-123");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/attach")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"secret":"test-secret-123","scope":"client"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("token").and_then(|t| t.as_str()).is_some());
        assert_eq!(json["session_type"], "capsule");
    }

    #[tokio::test]
    async fn attach_returns_shell_session_for_shell_scope() {
        let app = test_router("secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/attach")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"secret":"secret","scope":"shell"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["session_type"], "shell");
    }

    #[tokio::test]
    async fn attach_rejects_wrong_secret() {
        let app = test_router("correct-secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/attach")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"secret":"wrong-secret","scope":"client"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Verify that the attach route works when merged with other routers
    /// that have auth middleware. This catches the routing bug where
    /// auth middleware intercepts the public attach endpoint.
    #[tokio::test]
    async fn attach_route_not_intercepted_by_auth_middleware() {
        use crate::api::middleware::{auth_middleware, ApiState};
        use axum::middleware as axum_middleware;

        let registry = Arc::new(SessionRegistry::new(Arc::new(AuditLog::new())));

        let attach_state = AttachState {
            session_registry: registry.clone(),
            secret: "the-secret".to_string(),
            shells: AttachShells::default(),
        };
        let attach_routes = Router::new()
            .route("/api/auth/attach", post(attach))
            .with_state(attach_state);

        let api_state = ApiState {
            session_registry: registry,
        };
        let auth_routes = Router::new()
            .route("/api/session", axum::routing::get(|| async { "ok" }))
            .layer(axum_middleware::from_fn_with_state(
                api_state,
                auth_middleware,
            ));

        let app = Router::new().merge(attach_routes).merge(auth_routes);

        // Attach should work without Authorization header
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/attach")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"secret":"the-secret","scope":"client"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "attach endpoint should not require Authorization header"
        );
    }
}
