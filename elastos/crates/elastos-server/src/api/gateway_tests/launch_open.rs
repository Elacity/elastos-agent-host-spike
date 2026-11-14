//! D2a. Home opens a content capsule by its CID for the signed-in person, and
//! the page of the kept launch is served from it.

use super::*;

const LAUNCH: &str = "abababababababababababababababab";

fn home_cookie(authority: &TestPasskeyAuthority) -> String {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("localhost:61180"));
    gateway_home_token::home_session_cookie_header_for_token(&headers, &authority.home_token, false)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn open(
    app: &Router,
    cid: &str,
    cookie: Option<&str>,
    token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut request = test_browser_request("localhost:61180", "http://localhost:61180")
        .method("POST")
        .uri("/api/home/launch/content")
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header(COOKIE, cookie);
    }
    if let Some(token) = token {
        request = request.header("x-elastos-home-token", token);
    }
    let body = Body::from(json!({ "cid": cid }).to_string());
    let answer = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = answer.status();
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body.to_vec())
}

fn token_life(token: &str) -> (u64, u64) {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let payload = &envelope["payload"];
    (
        payload["iat"].as_u64().unwrap(),
        payload["exp"].as_u64().unwrap(),
    )
}

/// D2a-open. The signed-in person's Home session opens a set by its CID: the
/// gateway asks the Runtime's open as the shell, with a grant for `home` for
/// that person, and answers the page's name, its address under the launch,
/// and the page's own token, bound to that launch with the page as its
/// executable, for fifteen minutes at most, refused by every other check.
#[tokio::test]
async fn home_opens_a_set_by_its_cid_and_gets_its_pages_address_and_token() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-open").await;

    let (status, body) = open(&app, "bafy-good", Some(&home_cookie(&authority)), None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer["page"], "image-viewer");
    assert_eq!(
        answer["page_url"],
        format!("/launch/{LAUNCH}/page/browser/index.html")
    );
    let token = answer["token"].as_str().unwrap().to_string();

    let asked = runtime.kept_launch_reads.lock().await.clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0]["path"], "/api/launch/open");
    assert_eq!(
        asked[0]["bearer"], "Bearer shell-launch-open",
        "as the shell"
    );
    assert_eq!(asked[0]["body"], json!({ "cid": "bafy-good" }));
    let mut grant = HeaderMap::new();
    grant.insert(
        "x-elastos-home-token",
        asked[0]["token"].as_str().unwrap().parse().unwrap(),
    );
    let person =
        require_internal_shell_launch_grant_for_any_context(dir.path(), &grant, &[HOME_CAPSULE_ID])
            .expect("a grant for home");
    assert_eq!(
        person.principal_id(),
        authority.principal_id,
        "for the signed-in person"
    );

    let mut page = HeaderMap::new();
    page.insert("x-elastos-home-token", token.parse().unwrap());
    page.insert(HOST, "localhost:61180".parse().unwrap());
    page.insert("origin", "null".parse().unwrap());
    let (id, _, _) = require_launch_bound_token(dir.path(), &page, "image-viewer", false).unwrap();
    assert_eq!(id, LAUNCH);
    let refused = require_home_launch_token_for_any_context(dir.path(), &page, &["image-viewer"])
        .unwrap_err();
    assert!(
        refused.to_string().contains("bound to a content launch"),
        "{refused}"
    );
    let (issued, expires) = token_life(&token);
    assert!(
        expires > issued && expires - issued <= 15 * 60,
        "fifteen minutes at most: {issued} to {expires}"
    );
}

/// D2a-refused. Without Home's own session nothing is opened and the Runtime
/// is not asked: no session at all, or another app's token. The Runtime's
/// refusals are passed on as they are, by name, and no token is minted.
#[tokio::test]
async fn home_open_needs_homes_session_and_passes_refusals_on_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-open-refused").await;

    let (status, _) = open(&app, "bafy-good", None, None).await;
    assert!(!status.is_success(), "{status}");
    let other_app = app_token_for_authority(dir.path(), "assistant", &authority);
    let (status, _) = open(&app, "bafy-good", None, Some(&other_app)).await;
    assert!(!status.is_success(), "{status}");
    assert!(
        runtime.kept_launch_reads.lock().await.is_empty(),
        "the Runtime is not asked"
    );

    let cookie = home_cookie(&authority);
    let (status, body) = open(&app, "bafy-wrong", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = String::from_utf8_lossy(&body).to_string();
    assert!(body.starts_with("bundle_cid_mismatch"), "{body}");
    let (status, body) = open(&app, "bafy-full", Some(&cookie), None).await;
    assert_eq!(
        (status, body),
        (
            StatusCode::TOO_MANY_REQUESTS,
            b"too_many_open_launches".to_vec()
        )
    );
}

/// D2a-page. The page of a kept launch is served from it, as the Runtime
/// gives it: a document with the sandboxed app policy (`blob:` pictures
/// among what `img-src` allows), `nosniff`, `no-referrer` and the opaque
/// origin; an asset byte for byte, with no policy. A path that is not plain,
/// or an id that is no launch id, is `not_found` and the Runtime is not asked.
#[tokio::test]
async fn the_page_of_a_kept_launch_is_served_under_the_app_policy() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-page").await;
    let get = |uri: String| {
        let app = app.clone();
        async move {
            let request = Request::builder()
                .uri(uri)
                .header(HOST, "localhost:61180")
                .body(Body::empty())
                .unwrap();
            let answer = app.oneshot(request).await.unwrap();
            let status = answer.status();
            let headers = answer.headers().clone();
            let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, headers, body.to_vec())
        }
    };

    let (status, headers, body) = get(format!("/launch/{LAUNCH}/page/browser/index.html")).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, b"<html>the page</html>".to_vec())
    );
    let header = |name: &str| headers.get(name).map(|v| v.to_str().unwrap().to_string());
    let policy = header("content-security-policy").expect("the app policy");
    assert!(policy.starts_with("sandbox allow-scripts"), "{policy}");
    assert!(policy.contains(" blob:"), "{policy}");
    assert_eq!(
        header("x-content-type-options").as_deref(),
        Some("nosniff"),
        "nosniff"
    );
    assert_eq!(header("referrer-policy").as_deref(), Some("no-referrer"));
    assert_eq!(
        header("access-control-allow-origin").as_deref(),
        Some("null")
    );
    assert_eq!(
        header("content-type").as_deref(),
        Some("text/html; charset=utf-8")
    );

    let (status, headers, body) = get(format!("/launch/{LAUNCH}/page/browser/photos.js")).await;
    assert_eq!((status, body), (StatusCode::OK, b"export {};".to_vec()));
    assert!(headers.get("content-security-policy").is_none());
    let asked = runtime.kept_launch_reads.lock().await.len();
    assert_eq!(asked, 2);

    for uri in [
        format!("/launch/{LAUNCH}/page/browser%2F..%2Fsecret.html"),
        format!("/launch/{LAUNCH}/page/browser//index.html"),
        "/launch/not-a-launch/page/browser/index.html".to_string(),
    ] {
        let (status, _, body) = get(uri.clone()).await;
        assert_eq!(
            (status, body),
            (StatusCode::NOT_FOUND, b"not_found".to_vec()),
            "{uri}"
        );
    }
    assert_eq!(
        runtime.kept_launch_reads.lock().await.len(),
        asked,
        "the Runtime is not asked for a bad path"
    );
}
