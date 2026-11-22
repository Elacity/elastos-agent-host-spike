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
    // Home's own page sends Home's origin; an app's frame sends `null`.
    let origin = if token.is_some() {
        "null"
    } else {
        "http://localhost:61180"
    };
    let mut request = test_browser_request("localhost:61180", origin)
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

#[test]
fn cli_launch_grant_is_refused_by_wallet_authority_itself() {
    let dir = tempfile::tempdir().unwrap();
    let owner = passkey_authority(dir.path());
    let grant = owner_cli_home_launch_grant(dir.path(), &owner);
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", grant.parse().unwrap());
    let error =
        gateway_home_system::require_home_active_shell_wallet_authority(dir.path(), &headers)
            .expect_err("wallet authority must refuse the CLI launch grant");
    assert_eq!(error.to_string(), "home_cli_launch_grant_scope_mismatch");
}

#[test]
fn cli_launch_grant_is_refused_by_front_door_without_wallet_authority() {
    let dir = tempfile::tempdir().unwrap();
    let owner = passkey_authority(dir.path());
    let grant = owner_cli_home_launch_grant(dir.path(), &owner);
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", grant.parse().unwrap());
    let error = gateway_home_token::require_gateway_launch(dir.path(), &headers)
        .expect_err("front-door admission must refuse the CLI launch grant");
    assert_eq!(error.to_string(), "home_launch_grant_scope_mismatch");
}

#[tokio::test]
async fn owner_cli_issuer_limits_headless_launch_and_open_gates() {
    let dir = tempfile::tempdir().unwrap();
    let owner = passkey_authority(dir.path());
    let grant = owner_cli_home_launch_grant(dir.path(), &owner);
    let (issued, expires) = token_life(&grant);
    assert!(expires > issued && expires - issued <= HOME_LAUNCH_TOKEN_TTL_SECS);
    let app = gateway_router(test_state(dir.path()));

    let page_mint = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "http://localhost:61180")
                .method("POST")
                .uri("/api/apps/home/cli-launch-token")
                .header("x-elastos-home-token", owner.home_token.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page_mint.status(), StatusCode::METHOD_NOT_ALLOWED);

    let launch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/apps/home/launch")
                .header(HOST, "localhost:61180")
                .header("x-elastos-home-token", grant.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"target":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(launch.status(), StatusCode::BAD_REQUEST);

    for path in [
        "/api/apps/home/summary",
        "/api/apps/home/state",
        "/api/apps/home/appearance/preferences",
        "/api/apps/home/shared-content/get",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(HOST, "localhost:61180")
                    .header("x-elastos-home-token", grant.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }

    for path in ["/api/apps/home/launch", "/api/home/launch/content"] {
        let response = app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "http://localhost:61180")
                    .method("POST")
                    .uri(path)
                    .header("x-elastos-home-token", grant.as_str())
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let opened = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/home/launch/content")
                .header(HOST, "localhost:61180")
                .header("x-elastos-home-token", grant.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cid":"bafy-good"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn cli_issuer_refuses_guest_and_unbound_context() {
    let dir = tempfile::tempdir().unwrap();
    let guest = passkey_authority_with_name_role(
        dir.path(),
        Some("guest"),
        crate::auth::RuntimePrincipalRole::Guest,
    );
    let context = home_launch_token_context_from_parts(
        dir.path(),
        &guest.principal_id,
        &guest.session_id,
        Some(&guest.proof_binding_id),
        &guest.grant_id,
    )
    .unwrap();
    assert!(issue_home_cli_launch_grant_for_context(dir.path(), &context).is_err());
    let device = local_home_launch_token_context(dir.path()).unwrap();
    assert!(issue_home_cli_launch_grant_for_context(dir.path(), &device).is_err());
}

#[test]
fn cli_issuer_refuses_agent_principal() {
    let dir = tempfile::tempdir().unwrap();
    let agent = crate::auth::valid_agent::plant(dir.path());
    let context = home_launch_token_context_from_parts(
        dir.path(),
        &agent.principal_id,
        "session:agent-cli-issuer",
        None,
        "grant:agent-cli-issuer",
    )
    .unwrap();
    assert_eq!(
        context.root().kind(),
        Some(crate::auth::PrincipalKind::Agent)
    );
    let error = issue_home_cli_launch_grant_for_context(dir.path(), &context)
        .expect_err("agent principal must be refused");
    assert_eq!(error.to_string(), "a human Home owner is required");
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
    let person = require_internal_shell_content_open_context(dir.path(), &grant)
        .expect("the shell's content-open grant");
    assert_eq!(
        person.principal_id(),
        authority.principal_id,
        "for the signed-in person"
    );

    let mut page = HeaderMap::new();
    page.insert("x-elastos-home-token", token.parse().unwrap());
    page.insert(HOST, "localhost:61180".parse().unwrap());
    page.insert("origin", "null".parse().unwrap());
    let (id, content_name, _, _) =
        require_launch_bound_token(dir.path(), &page, "image-viewer", false).unwrap();
    assert_eq!(id, LAUNCH);
    assert_eq!(content_name, "photo-set");
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

#[tokio::test]
async fn content_open_gate_accepts_page_and_cli_before_runtime_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    let (status, body) = open(&app, "bafy-good", Some(&home_cookie(&authority)), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"local runtime is not running");

    let cli = owner_cli_home_launch_grant(dir.path(), &authority);
    let answer = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/home/launch/content")
                .header(HOST, "localhost:61180")
                .header("x-elastos-home-token", cli)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cid":"bafy-good"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn content_open_names_non_home_page_and_accepts_cli_grant() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    let runtime = start_fake_runtime(
        dir.path(),
        Arc::new(TokioMutex::new(FakePeerBus::default())),
        "launch-open-cli",
    )
    .await;
    let other = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/home/launch/content")
                .header(HOST, "localhost:61180")
                .header("origin", "http://localhost:61180")
                .header("sec-fetch-site", "same-origin")
                .header("referer", "http://localhost:61180/apps/system/")
                .header(COOKIE, home_cookie(&authority))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cid":"bafy-good"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        axum::body::to_bytes(other.into_body(), usize::MAX)
            .await
            .unwrap(),
        "home_page_only"
    );
    assert!(runtime.kept_launch_reads.lock().await.is_empty());

    let cli = owner_cli_home_launch_grant(dir.path(), &authority);
    let opened = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/home/launch/content")
                .header(HOST, "localhost:61180")
                .header("x-elastos-home-token", cli)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cid":"bafy-good"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    assert_eq!(runtime.kept_launch_reads.lock().await.len(), 1);
}

#[tokio::test]
async fn content_open_refuses_agent_home_page_before_minting() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let response = app
        .oneshot(
            test_browser_request("localhost:61180", "http://localhost:61180")
                .method("POST")
                .uri("/api/home/launch/content")
                .header("x-elastos-home-token", agent_home_token(dir.path()))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"cid":"bafy-good"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        gateway_home_token::GATEWAY_AGENT_REFUSAL.as_bytes()
    );
}

/// D2a-address. The page's address takes each part of the entrypoint
/// percent-encoded, so a file name with a space or a `#` (a manifest allows
/// both) names that file and no other. A 200 from the Runtime in any other
/// shape (an id that is not 32 hex, an entrypoint or page name that is not
/// plain) is a 502, and no token is minted.
#[tokio::test]
async fn home_open_encodes_the_pages_address_and_uses_only_a_well_formed_answer() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    let bus = Arc::new(TokioMutex::new(FakePeerBus::default()));
    let runtime = start_fake_runtime(dir.path(), bus, "launch-open-address").await;
    let cookie = home_cookie(&authority);

    let (status, body) = open(&app, "bafy-odd", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        answer["page_url"],
        format!("/launch/{LAUNCH}/page/browser/my%20page%231.html")
    );
    // The address loads that file: the gateway's page route decodes the path
    // and asks the Runtime for the same name, each part encoded again.
    let request = Request::builder()
        .uri(answer["page_url"].as_str().unwrap())
        .header(HOST, "localhost:61180")
        .body(Body::empty())
        .unwrap();
    let served = app.clone().oneshot(request).await.unwrap();
    assert_eq!(served.status(), StatusCode::OK);
    let body = axum::body::to_bytes(served.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"<html>the odd page</html>");
    let asked = runtime.kept_launch_reads.lock().await.clone();
    assert_eq!(
        asked.last().unwrap()["path"],
        format!("/api/launch/{LAUNCH}/page/browser/my%20page%231.html")
    );

    for cid in ["bafy-badid", "bafy-badentry", "bafy-badpage"] {
        let (status, body) = open(&app, cid, Some(&cookie), None).await;
        assert_eq!(
            (status, String::from_utf8_lossy(&body).to_string()),
            (
                StatusCode::BAD_GATEWAY,
                "runtime open answered oddly".to_string()
            ),
            "{cid}"
        );
    }
}

/// D2a-refused. Without Home's own session nothing is opened and the Runtime
/// is not asked: no session at all, or another app's token sent as that app's
/// frame sends it (`Origin: null`), so that only Home's own check refuses it. The Runtime's
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
    assert_eq!(
        String::from_utf8_lossy(&body),
        "bundle_cid_mismatch: the slot's files do not recompute to the CID asked for"
    );
    let (status, body) = open(&app, "bafy-backslash", Some(&cookie), None).await;
    assert_eq!(
        (status, String::from_utf8_lossy(&body).to_string()),
        (
            StatusCode::BAD_REQUEST,
            "page_entrypoint_not_plain".to_string()
        )
    );
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
