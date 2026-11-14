//! D1b. The page's two reads of its kept content launch at the gateway, and
//! the rule that a token bound to a kept launch opens nothing else.

use super::*;

const PAGE: &str = "image-viewer";

fn launch_id() -> String {
    "ab".repeat(16)
}

/// A page's token bound to `resource`, with `page` as its executable, as the
/// open will mint it.
fn page_token(dir: &std::path::Path, resource: &str, page: &str) -> String {
    let context = local_home_launch_token_context(dir).unwrap();
    issue_home_projection_launch_token_with_context(dir, resource, page, &context).unwrap()
}

async fn read(
    app: &Router,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut request = Request::builder()
        .uri(uri)
        .header(HOST, "localhost:61180")
        .header("origin", "null");
    if let Some(token) = token {
        request = request.header("x-elastos-home-token", token);
    }
    let answer = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = answer.status();
    let store = answer
        .headers()
        .get("cache-control")
        .map(|value| value.to_str().unwrap().to_string());
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, store, body.to_vec())
}

fn launch_reads_audited(dir: &std::path::Path) -> Vec<String> {
    crate::auth::load_auth_state(dir)
        .unwrap()
        .audit
        .iter()
        .filter(|event| event.event_type == "viewer.launch.read")
        .map(|event| event.result.clone())
        .collect()
}

/// D1b-read. The page's own token reads its kept launch: the gateway asks the
/// Runtime as the shell, carrying that same token and no browser marks, and
/// passes the bytes back, never to be stored. Each read is audited once.
#[tokio::test]
async fn a_pages_token_reads_its_kept_launch_through_the_runtime_as_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let state = library_test_state(dir.path()).await;
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-reads").await;
    let app = gateway_router(state);
    let id = launch_id();
    let token = page_token(dir.path(), &format!("elastos://launch/{id}"), PAGE);
    let base = format!("/api/viewers/{PAGE}/launch");

    let (status, store, body) =
        read(&app, &format!("{base}/output/playlist.json"), Some(&token)).await;
    assert_eq!((status, body), (StatusCode::OK, b"[1]".to_vec()));
    assert_eq!(store.as_deref(), Some("no-store"));
    let (status, _, body) =
        read(&app, &format!("{base}/content/images/01.png"), Some(&token)).await;
    assert_eq!((status, body), (StatusCode::OK, b"a picture".to_vec()));

    let asked = runtime.kept_launch_reads.lock().await.clone();
    assert_eq!(asked.len(), 2);
    let paths: Vec<&str> = asked
        .iter()
        .map(|ask| ask["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            format!("/api/launch/{id}/output/playlist.json"),
            format!("/api/launch/{id}/content/images/01.png")
        ]
    );
    for ask in &asked {
        assert_eq!(ask["bearer"], "Bearer shell-launch-reads", "as the shell");
        assert_eq!(ask["token"], token.as_str(), "the page's own token");
        assert_eq!(ask["origin"], serde_json::Value::Null, "no browser marks");
    }
    assert_eq!(launch_reads_audited(dir.path()), ["ok", "ok"]);
}

/// D1b-bound. A token bound to a kept launch opens no other Home check: the
/// front door refuses it on a viewer route of the same viewer, and the shared
/// checks every other route goes through (a wallet's, the front door's for
/// any other path, the one rooms and sites use) refuse it by name. Tokens
/// bound to anything else are refused by the launch reads' check.
#[tokio::test]
async fn a_launch_bound_token_opens_no_other_home_check() {
    let dir = tempfile::tempdir().unwrap();
    let state = library_test_state(dir.path()).await;
    let app = gateway_router(state);
    let bound = format!("elastos://launch/{}", launch_id());
    let token = page_token(dir.path(), &bound, GBA_EMULATOR_CAPSULE_ID);

    let (status, _, body) = read(&app, "/api/viewers/gba-emulator/library", Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&body)
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    headers.insert(HOST, "localhost:61180".parse().unwrap());
    headers.insert("origin", "null".parse().unwrap());
    for apps in [
        &[GBA_EMULATOR_CAPSULE_ID][..],
        &["wallet", GBA_EMULATOR_CAPSULE_ID][..],
    ] {
        let refused = require_home_launch_token_for_any_context(dir.path(), &headers, apps)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("bound to a content launch"), "{refused}");
    }
    for path in [
        "/api/viewers/gba-emulator/library",
        "/api/apps/wallet/wallet/summary",
    ] {
        let refused = gateway_home_token::require_gateway_launch_for(dir.path(), &headers, path)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("bound to a content launch"),
            "{path}: {refused}"
        );
    }
    let refused = gateway_home_token::require_gateway_launch(dir.path(), &headers)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("bound to a content launch"), "{refused}");

    let other = page_token(dir.path(), "gba-ucity", GBA_EMULATOR_CAPSULE_ID);
    headers.insert("x-elastos-home-token", other.parse().unwrap());
    let refused = require_launch_bound_token(dir.path(), &headers, GBA_EMULATOR_CAPSULE_ID, false)
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("not bound to a content launch"),
        "{refused}"
    );
}

/// D1b-else. Nothing else reads, and the Runtime is not asked: no token, the
/// person's Home token, a token bound to another resource or naming another
/// page are refused at the front door; with the page's own token, a path
/// that is not plain or an output name that is not one plain name (`..`, a
/// name with a `/`) answers `not_found`. The fake Runtime records every ask
/// under `/api/launch/`, also one no route of it matches, so none slips by.
/// The Runtime's own `not_found` is passed on.
#[tokio::test]
async fn anything_else_is_not_found_and_the_runtime_is_not_asked() {
    let dir = tempfile::tempdir().unwrap();
    let state = library_test_state(dir.path()).await;
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-reads-else").await;
    let app = gateway_router(state);
    let id = launch_id();
    let bound = format!("elastos://launch/{id}");
    let own = page_token(dir.path(), &bound, PAGE);
    let base = format!("/api/viewers/{PAGE}/launch");
    let home = issue_home_launch_token(dir.path(), "home").unwrap();
    let elsewhere = page_token(dir.path(), "gba-ucity", PAGE);
    let other_page = page_token(dir.path(), &bound, "other-viewer");

    let refused_at_the_door = StatusCode::FORBIDDEN;
    for token in [
        None,
        Some(home.as_str()),
        Some(elsewhere.as_str()),
        Some(other_page.as_str()),
    ] {
        let (status, _, _) = read(&app, &format!("{base}/output/playlist.json"), token).await;
        assert_eq!(status, refused_at_the_door, "{token:?}");
    }
    for uri in [
        format!("{base}/content/x%2F..%2Fcapsule.json"),
        format!("{base}/content/images//01.png"),
        format!("{base}/output/.."),
        format!("{base}/output/a%2Fb"),
    ] {
        let (status, _, body) = read(&app, &uri, Some(&own)).await;
        assert_eq!(
            (status, body),
            (StatusCode::NOT_FOUND, b"not_found".to_vec()),
            "{uri}"
        );
    }
    assert!(
        runtime.kept_launch_reads.lock().await.is_empty(),
        "the Runtime is not asked"
    );

    let (status, _, body) =
        read(&app, &format!("{base}/content/images/none.png"), Some(&own)).await;
    assert_eq!(
        (status, body),
        (StatusCode::NOT_FOUND, b"not_found".to_vec())
    );
    assert_eq!(
        runtime.kept_launch_reads.lock().await.len(),
        1,
        "asked once"
    );
    assert_eq!(
        launch_reads_audited(dir.path()),
        [
            "not_found",
            "not_found",
            "not_found",
            "not_found",
            "not_found"
        ],
        "each read the page's own token makes is audited once"
    );
}
