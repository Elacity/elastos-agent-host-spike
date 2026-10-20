//! The Photos surface's read-only seam (viewer_gateway.rs "Photos surface")
//! and how Home binds a Photos launch.

use super::*;

use crate::api::viewer_gateway::{
    count_photos_unadmitted_at, flush_photos_unadmitted, PhotosPins, PhotosUnadmittedWindow,
    PHOTOS_LAUNCH_TOKEN_TTL_SECS, PHOTOS_MAX_PINS, PHOTOS_PLAYLIST_URI, PHOTOS_VIEWER,
};

const PNG_A: &[u8] = b"\x89PNG\r\n\x1a\nimage-a";
const PNG_C: &[u8] = b"\x89PNG\r\n\x1a\nimage-c";
const UNLISTED: &[u8] = b"\x89PNG\r\n\x1a\nnot-in-the-playlist";

struct Photos {
    dir: tempfile::TempDir,
    app: axum::Router,
    authority: TestPasskeyAuthority,
    library_token: String,
}

impl Photos {
    fn root(&self) -> String {
        crate::auth::principal_localhost_root(&self.authority.principal_id)
    }

    fn playlist_path(&self) -> String {
        format!("{}/.AppData/App/photo-viewer/playlist.json", self.root())
    }

    /// Writes through the Library provider, as the Library app would.
    async fn write(&self, rooted_uri: &str, bytes: &[u8]) {
        let body = json!({
            "uri": rooted_uri,
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        });
        let response = self
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .method("POST")
                    .uri("/api/provider/object/write")
                    .header("x-elastos-home-token", &self.library_token)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let payload = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "write {rooted_uri}: {}",
            String::from_utf8_lossy(&payload)
        );
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["status"], "ok", "write {rooted_uri}: {payload}");
    }

    async fn write_playlist(&self, playlist: &serde_json::Value) {
        self.write(
            &self.playlist_path(),
            &serde_json::to_vec(playlist).unwrap(),
        )
        .await;
    }

    /// A Photos launch token for this person, bound to `selected`.
    fn token(&self, selected: &str) -> String {
        photos_token(self.dir.path(), &self.authority, selected)
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
        request(&self.app, "GET", path, token).await
    }
}

fn launch_context(
    data_dir: &std::path::Path,
    authority: &TestPasskeyAuthority,
) -> HomeLaunchTokenContext {
    let now = crate::auth::now_ts();
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", uuid_like_token()),
        session_id: format!("auth:{}", uuid_like_token()),
        principal_id: authority.principal_id.clone(),
        proof_binding_id: authority.proof_binding_id.clone(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        // Projection tokens carry Home as their authority actor, as when
        // Home launches Photos.
        apps: vec![HOME_CAPSULE_ID.to_string()],
    };
    crate::auth::store_session_grant(data_dir, grant.clone()).unwrap();
    HomeLaunchTokenContext {
        principal_id: grant.principal_id,
        session_id: grant.session_id,
        proof_binding_id: Some(grant.proof_binding_id),
        grant_id: grant.grant_id,
    }
}

fn photos_token(
    data_dir: &std::path::Path,
    authority: &TestPasskeyAuthority,
    selected: &str,
) -> String {
    issue_home_projection_launch_token_with_ttl(
        data_dir,
        selected,
        PHOTOS_VIEWER,
        &launch_context(data_dir, authority),
        PHOTOS_LAUNCH_TOKEN_TTL_SECS,
    )
    .unwrap()
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = test_browser_request("localhost:61180", "null")
        .method(method)
        .uri(path);
    if let Some(token) = token {
        builder = builder.header("x-elastos-home-token", token);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

fn playlist(items: serde_json::Value) -> serde_json::Value {
    json!({
        "schema": "elastos.photo-viewer.playlist/v1",
        "album": "localhost://Users/self/.AppData/App/photo-viewer/album.json",
        "items": items,
        "skipped": [{
            "order": 1,
            "uri": "localhost://Users/self/Pictures/b.gif",
            "reason": "wrong_type",
            "message": "not PNG, JPEG or WebP",
        }],
    })
}

fn item(order: u64, uri: &str) -> serde_json::Value {
    json!({
        "order": order, "uri": uri, "mime": "image/png",
        "width": 1, "height": 1, "duration_ms": 5000,
    })
}

/// Photos installed as a viewer, three Pictures, and a playlist that lists
/// a.png at 0 and c.png at 2, with position 1 skipped.
async fn photos() -> Photos {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(library_test_state(dir.path()).await);
    let authority = passkey_authority_with_name(dir.path(), Some("admin"));
    let library_token = app_token_for_authority(dir.path(), LIBRARY_CAPSULE_ID, &authority);
    write_test_static_capsule(
        dir.path(),
        PHOTOS_VIEWER,
        "viewer",
        "Test Photos viewer",
        "<!doctype html><title>Photos</title>",
    );
    let photos = Photos {
        dir,
        app,
        authority,
        library_token,
    };
    let root = photos.root();
    photos.write(&format!("{root}/Pictures/a.png"), PNG_A).await;
    photos.write(&format!("{root}/Pictures/c.png"), PNG_C).await;
    photos
        .write(&format!("{root}/Pictures/unlisted.png"), UNLISTED)
        .await;
    photos
        .write(
            &format!("{root}/Documents/secret.png"),
            b"\x89PNG\r\n\x1a\nsecret",
        )
        .await;
    photos
        .write(&format!("{root}/Pictures/notes.txt"), b"not an image")
        .await;
    photos
        .write_playlist(&playlist(json!([
            item(0, "localhost://Users/self/Pictures/a.png"),
            item(2, "localhost://Users/self/Pictures/c.png"),
        ])))
        .await;
    photos
}

/// A second person with their own passkey, so their own principal root.
fn other_person(data_dir: &std::path::Path, mine: &TestPasskeyAuthority) -> TestPasskeyAuthority {
    let other = passkey_authority_with_name_role_credential(
        data_dir,
        Some("other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "gateway-test-photos-other-passkey",
    );
    assert_ne!(other.principal_id, mine.principal_id);
    other
}

fn photos_audit_events(data_dir: &std::path::Path) -> Vec<(String, String, String)> {
    photos_audit_records(data_dir)
        .into_iter()
        .map(|event| (event.event_type, event.result, event.reason))
        .collect()
}

fn photos_audit_records(data_dir: &std::path::Path) -> Vec<RuntimeAuditEventV1> {
    crate::auth::load_auth_state(data_dir)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| event.event_type.starts_with("photos.viewer."))
        .collect()
}

/// Library viewer events written for the Photos viewer (the per-operation
/// stat and read records Photos must not leave).
fn library_viewer_events_for_photos(data_dir: &std::path::Path) -> usize {
    crate::auth::load_auth_state(data_dir)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| {
            event.event_type.starts_with("library.viewer.")
                && event.capsule_id.as_deref() == Some(PHOTOS_VIEWER)
        })
        .count()
}

/// The signed launch id inside a launch token.
fn token_launch_id(token: &str) -> String {
    let envelope: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap(),
    )
    .unwrap();
    envelope["payload"]["launch_id"]
        .as_str()
        .unwrap()
        .to_string()
}

const PLAYLIST_ROUTE: &str = "/api/viewers/image-viewer/playlist";

fn item_route(order: &str) -> String {
    format!("/api/viewers/image-viewer/playlist/item/{order}")
}

// --- served ---------------------------------------------------------------

#[tokio::test]
async fn photos_serves_its_bound_playlist_and_the_items_it_lists() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);

    let (status, body) = photos.get(PLAYLIST_ROUTE, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let served: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        served["items"][0]["uri"],
        "localhost://Users/self/Pictures/a.png"
    );

    let (status, body) = photos.get(&item_route("0"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, PNG_A);
    let (status, body) = photos.get(&item_route("2"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG_C);

    let events = photos_audit_events(photos.dir.path());
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(events.iter().all(|(_, result, _)| result == "served"));
    let playlist = photos.playlist_path();
    assert!(
        events[0]
            .2
            .starts_with(&format!("playlist={playlist} sha256="))
            && events[0].2.contains("position=- item=- result=served"),
        "{}",
        events[0].2
    );
    assert!(
        events[1]
            .2
            .contains("position=0 item=localhost://Users/self/Pictures/a.png result=served"),
        "{}",
        events[1].2
    );
}

// --- launch token ------------------------------------------------------------

/// Without a valid launch token the gateway front door refuses before any
/// route runs (gateway_frontdoor.rs `gateway_admission`).
fn refused_at_the_front_door(status: StatusCode, body: &[u8]) -> bool {
    status == StatusCode::FORBIDDEN
        && String::from_utf8_lossy(body).contains("requires an admitted host and caller")
}

#[tokio::test]
async fn photos_refuses_without_a_launch_token() {
    let photos = photos().await;
    for path in [PLAYLIST_ROUTE.to_string(), item_route("0")] {
        for token in [None, Some("not-a-token")] {
            let (status, body) = photos.get(&path, token).await;
            assert!(
                refused_at_the_front_door(status, &body),
                "{path} {token:?}: {status}"
            );
        }
    }
    assert!(photos_audit_events(photos.dir.path()).is_empty());
}

#[tokio::test]
async fn photos_refuses_an_expired_launch_token() {
    let photos = photos().await;
    let expired = super::gateway_home_token::issue_expired_home_projection_launch_token_with_ttl(
        photos.dir.path(),
        PHOTOS_PLAYLIST_URI,
        PHOTOS_VIEWER,
        &launch_context(photos.dir.path(), &photos.authority),
        PHOTOS_LAUNCH_TOKEN_TTL_SECS,
    )
    .unwrap();
    let (status, body) = photos.get(&item_route("0"), Some(&expired)).await;
    assert!(refused_at_the_front_door(status, &body), "{status}");
    assert_ne!(body, PNG_A);
}

#[tokio::test]
async fn photos_refuses_another_viewers_launch_token() {
    let photos = photos().await;
    write_test_static_capsule(
        photos.dir.path(),
        DOCUMENTS_CAPSULE_ID,
        "viewer",
        "Test Documents viewer",
        "<!doctype html><title>Documents</title>",
    );
    let documents =
        app_token_for_authority(photos.dir.path(), DOCUMENTS_CAPSULE_ID, &photos.authority);
    let documents_with_playlist = issue_home_projection_launch_token_with_ttl(
        photos.dir.path(),
        PHOTOS_PLAYLIST_URI,
        DOCUMENTS_CAPSULE_ID,
        &launch_context(photos.dir.path(), &photos.authority),
        PHOTOS_LAUNCH_TOKEN_TTL_SECS,
    )
    .unwrap();
    for token in [documents, documents_with_playlist] {
        let (status, _) = photos.get(&item_route("0"), Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn photos_refuses_a_launch_not_bound_to_its_playlist() {
    let photos = photos().await;
    for selected in [
        // Opened from the Library for one image: no playlist.
        PHOTOS_VIEWER,
        // A playlist from some other launch.
        "localhost://Users/self/.AppData/App/photo-viewer/other-playlist.json",
        "localhost://Users/self/Pictures/a.png",
    ] {
        let token = photos.token(selected);
        for path in [PLAYLIST_ROUTE.to_string(), item_route("0")] {
            let (status, body) = photos.get(&path, Some(&token)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{selected} {path}");
            assert!(String::from_utf8_lossy(&body).contains("not bound to a playlist"));
        }
    }
}

#[tokio::test]
async fn photos_reads_only_the_playlist_of_the_launching_person() {
    let photos = photos().await;
    let other = other_person(photos.dir.path(), &photos.authority);
    let other_token = photos_token(photos.dir.path(), &other, PHOTOS_PLAYLIST_URI);
    // The other person has no playlist of their own, and never gets this one.
    let (status, _) = photos.get(PLAYLIST_ROUTE, Some(&other_token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = photos.get(&item_route("0"), Some(&other_token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_photos_token_cannot_use_the_generic_viewer_read() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    let uri = format!("{}/Pictures/unlisted.png", photos.root());
    let encoded = uri.replace(':', "%3A").replace('/', "%2F");
    let (status, body) = photos
        .get(
            &format!("/api/viewers/image-viewer/library-object?uri={encoded}&raw=true"),
            Some(&token),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_ne!(body, UNLISTED);
}

// --- position ------------------------------------------------------------------

#[tokio::test]
async fn photos_refuses_a_position_out_of_range_or_not_listed() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    // 1 is the skipped entry; 3 and beyond are not in the playlist.
    for order in ["1", "3", "99", "18446744073709551615"] {
        let (status, body) = photos.get(&item_route(order), Some(&token)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{order}");
        assert!(String::from_utf8_lossy(&body).contains("not a playable item"));
    }
    for order in ["-1", "x", "0x1", "1.0", "18446744073709551616"] {
        let (status, _) = photos.get(&item_route(order), Some(&token)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{order}");
    }
    let events = photos_audit_events(photos.dir.path());
    assert_eq!(events.len(), 9, "{events:?}");
    assert!(events.iter().all(|(_, result, _)| result == "refused"));
    assert!(events[0].2.contains("position=1 item=- result=refused 404"));
}

#[tokio::test]
async fn photos_has_no_path_input() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    let unlisted = "localhost%3A%2F%2FUsers%2Fself%2FPictures%2Funlisted.png";
    for path in [
        format!("{}?uri={unlisted}", item_route("0")),
        format!("{}?path={unlisted}", item_route("0")),
    ] {
        let (status, body) = photos.get(&path, Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body, PNG_A,
            "the query is ignored; position 0 is still a.png"
        );
    }
    let (status, _) = photos
        .get(&format!("{}/unlisted.png", item_route("0")), Some(&token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- items the playlist names ------------------------------------------------------

#[tokio::test]
async fn photos_refuses_items_outside_pictures_or_not_viewable() {
    let photos = photos().await;
    let root = photos.root();
    let cases = [
        "localhost://Users/self/Documents/secret.png",
        "localhost://Users/self/Pictures/../Documents/secret.png",
        "localhost://Users/self/Pictures/./a.png",
        "localhost://Users/self/Pictures//a.png",
        "localhost://Users/self/Pictures/a.png?x=1",
        "localhost://Users/other/Pictures/a.png",
        "elastos://object/read",
    ];
    let mut items: Vec<serde_json::Value> = cases
        .iter()
        .enumerate()
        .map(|(index, uri)| item(10 + index as u64, uri))
        .collect();
    items.push(item(30, &format!("{root}/Pictures/a.png")));
    items.push(item(31, "localhost://Users/self/Pictures/notes.txt"));
    photos
        .write_playlist(&playlist(serde_json::Value::Array(items)))
        .await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);

    for (index, uri) in cases.iter().enumerate() {
        let (status, body) = photos
            .get(&item_route(&(10 + index).to_string()), Some(&token))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_ne!(body, b"\x89PNG\r\n\x1a\nsecret".to_vec());
    }
    // Only the Users/self alias names Pictures; a rooted path is refused too.
    let (status, _) = photos.get(&item_route("30"), Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Under Pictures, but not a type the Photos viewer opens.
    let (status, body) = photos.get(&item_route("31"), Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn photos_refuses_a_malformed_or_oversize_playlist() {
    let photos = photos().await;
    for bad in [
        json!({ "schema": "other/v1", "items": [] }),
        json!({ "schema": "elastos.photo-viewer.playlist/v1" }),
        playlist(json!([
            item(0, "localhost://Users/self/Pictures/a.png"),
            item(0, "localhost://Users/self/Pictures/c.png"),
        ])),
        playlist(json!([{ "uri": "localhost://Users/self/Pictures/a.png" }])),
    ] {
        photos.write_playlist(&bad).await;
        // A fresh launch for each playlist: a launch keeps the one it read.
        let token = photos.token(PHOTOS_PLAYLIST_URI);
        let (status, body) = photos.get(&item_route("0"), Some(&token)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let mut oversize = playlist(json!([item(0, "localhost://Users/self/Pictures/a.png")]));
    oversize["padding"] = json!("x".repeat(64 * 1024));
    photos.write_playlist(&oversize).await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    for path in [PLAYLIST_ROUTE.to_string(), item_route("0")] {
        let (status, _) = photos.get(&path, Some(&token)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
}

#[tokio::test]
async fn photos_refuses_when_the_playlist_is_missing() {
    let photos = photos().await;
    let other = other_person(photos.dir.path(), &photos.authority);
    let token = photos_token(photos.dir.path(), &other, PHOTOS_PLAYLIST_URI);
    let (status, _) = photos.get(PLAYLIST_ROUTE, Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- read only -------------------------------------------------------------------

#[tokio::test]
async fn photos_has_no_write_route() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        for path in [PLAYLIST_ROUTE.to_string(), item_route("0")] {
            let (status, _) = request(&photos.app, method, &path, Some(&token)).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        }
    }
    let (status, body) = photos.get(&item_route("0"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG_A, "the playlist and items are unchanged");
}

#[tokio::test]
async fn photos_requires_the_installed_photos_viewer() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    std::fs::remove_dir_all(photos.dir.path().join("capsules").join(PHOTOS_VIEWER)).unwrap();
    let (status, _) = photos.get(&item_route("0"), Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- Home binds the launch ---------------------------------------------------------

async fn home_launch(
    dir: &std::path::Path,
    app: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/apps/home/launch")
                .header(HOST, "localhost:61180")
                .header("origin", "http://localhost:61180")
                .header("sec-fetch-site", "same-origin")
                .header("x-elastos-home-token", home_app_token(dir))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(json!({})))
}

/// The signed payload of the launch token in a launch route's fragment.
fn launched_token_payload(launch: &serde_json::Value) -> serde_json::Value {
    let route = url::Url::parse("http://localhost")
        .unwrap()
        .join(launch["route"].as_str().unwrap())
        .unwrap();
    let token = url::form_urlencoded::parse(route.fragment().unwrap().as_bytes())
        .find_map(|(key, value)| (key == "home_token").then(|| value.into_owned()))
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap(),
    )
    .unwrap();
    envelope["payload"].clone()
}

#[tokio::test]
async fn home_binds_the_photos_playlist_with_a_short_lived_token() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(library_test_state(dir.path()).await);
    write_test_static_capsule(
        dir.path(),
        PHOTOS_VIEWER,
        "viewer",
        "Photos",
        "<title>Photos</title>",
    );

    let (status, launch) = home_launch(
        dir.path(),
        &app,
        json!({ "target": PHOTOS_VIEWER, "selected_resource": PHOTOS_PLAYLIST_URI }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{launch}");
    assert_eq!(launch["title"], "Photos");
    let payload = launched_token_payload(&launch);
    assert_eq!(
        payload["launch_context"]["selected_resource"],
        PHOTOS_PLAYLIST_URI
    );
    assert_eq!(payload["launch_context"]["executable_actor"], PHOTOS_VIEWER);
    assert_eq!(
        payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
        PHOTOS_LAUNCH_TOKEN_TTL_SECS
    );

    // Without a selected resource (opened from the Library for one image)
    // no playlist is bound and the token keeps the default lifetime.
    let (status, launch) = home_launch(dir.path(), &app, json!({ "target": PHOTOS_VIEWER })).await;
    assert_eq!(status, StatusCode::OK, "{launch}");
    let payload = launched_token_payload(&launch);
    assert_eq!(
        payload["launch_context"]["selected_resource"],
        PHOTOS_VIEWER
    );
    assert_eq!(
        payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
        12 * 60 * 60
    );
}

#[tokio::test]
async fn home_cannot_bind_anything_else() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(library_test_state(dir.path()).await);
    write_test_static_capsule(
        dir.path(),
        PHOTOS_VIEWER,
        "viewer",
        "Photos",
        "<title>Photos</title>",
    );
    write_test_static_capsule(
        dir.path(),
        DOCUMENTS_CAPSULE_ID,
        "viewer",
        "Documents",
        "<title>Documents</title>",
    );
    for body in [
        json!({ "target": PHOTOS_VIEWER, "selected_resource": "localhost://Users/self/Documents/a.json" }),
        json!({ "target": PHOTOS_VIEWER, "selected_resource": "localhost://Users/self/.AppData/App/photo-viewer/other.json" }),
        json!({ "target": PHOTOS_VIEWER, "selected_resource": "" }),
        json!({ "target": DOCUMENTS_CAPSULE_ID, "selected_resource": PHOTOS_PLAYLIST_URI }),
        json!({ "target": DOCUMENTS_CAPSULE_ID, "selected_resource": DOCUMENTS_CAPSULE_ID }),
    ] {
        let (status, response) = home_launch(dir.path(), &app, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
    }
    // Other targets keep the default lifetime.
    let (status, launch) =
        home_launch(dir.path(), &app, json!({ "target": DOCUMENTS_CAPSULE_ID })).await;
    assert_eq!(status, StatusCode::OK, "{launch}");
    let payload = launched_token_payload(&launch);
    assert_eq!(
        payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
        12 * 60 * 60
    );
}

// --- one audit record per request, and the pinned playlist --------------------------

#[tokio::test]
async fn each_photos_request_leaves_exactly_one_audit_record() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    let launch_id = token_launch_id(&token);
    // Served and refused reads, item and playlist routes.
    let paths = [
        item_route("0"),
        item_route("2"),
        item_route("1"),
        item_route("x"),
        item_route("0"),
        PLAYLIST_ROUTE.to_string(),
        item_route("2"),
    ];
    for (count, path) in paths.iter().enumerate() {
        photos.get(path, Some(&token)).await;
        let records = photos_audit_records(photos.dir.path());
        assert_eq!(records.len(), count + 1, "after {path}");
    }
    let records = photos_audit_records(photos.dir.path());
    assert_eq!(
        library_viewer_events_for_photos(photos.dir.path()),
        0,
        "the internal stat and read leave no records"
    );
    let ids: std::collections::BTreeSet<&str> = records
        .iter()
        .map(|event| event.event_id.as_str())
        .collect();
    assert_eq!(ids.len(), records.len(), "record ids are unique");
    for record in &records {
        assert!(
            record.event_id.contains(&format!(":{launch_id}:")),
            "the id names the launch: {}",
            record.event_id
        );
        assert_eq!(record.challenge_id.as_deref(), Some(launch_id.as_str()));
        assert_eq!(
            record.principal_id.as_deref(),
            Some(photos.authority.principal_id.as_str())
        );
    }
}

#[tokio::test]
async fn a_refusal_after_the_token_leaves_one_record() {
    let photos = photos().await;
    let unbound = photos.token(PHOTOS_VIEWER);
    for path in [PLAYLIST_ROUTE.to_string(), item_route("0")] {
        let (status, _) = photos.get(&path, Some(&unbound)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let events = photos_audit_events(photos.dir.path());
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(events.iter().all(
        |(_, result, reason)| result == "refused" && reason.contains("not bound to a playlist")
    ));
}

#[tokio::test]
async fn a_launch_keeps_the_playlist_it_read_first() {
    let photos = photos().await;
    let token = photos.token(PHOTOS_PLAYLIST_URI);
    let (status, body) = photos.get(&item_route("0"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG_A);

    // Another writer swaps the playlist during the launch.
    photos
        .write_playlist(&playlist(json!([item(
            0,
            "localhost://Users/self/Pictures/unlisted.png"
        )])))
        .await;
    for path in [item_route("0"), PLAYLIST_ROUTE.to_string()] {
        let (status, body) = photos.get(&path, Some(&token)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
        assert_ne!(body, UNLISTED);
        assert!(String::from_utf8_lossy(&body).contains("changed during this launch"));
    }
    // A new launch reads the new playlist.
    let fresh = photos.token(PHOTOS_PLAYLIST_URI);
    let (status, body) = photos.get(&item_route("0"), Some(&fresh)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, UNLISTED);
}

// ---- Refusals before the token check ----

fn unadmitted_events(data_dir: &std::path::Path) -> Vec<RuntimeAuditEventV1> {
    photos_audit_records(data_dir)
        .into_iter()
        .filter(|event| event.event_type == "photos.viewer.unadmitted")
        .collect()
}

#[test]
fn an_unknown_route_or_code_cannot_create_a_key() {
    let mut window = PhotosUnadmittedWindow::new(0, 16);
    window.add("item", "<script>alert(1)</script>");
    window.add(
        "/api/viewers/image-viewer/playlist/item/../../x",
        "token_refused",
    );
    window.add("item", "token_refused");
    window.add("playlist", "missing_token");
    let keys: Vec<_> = window.counts.keys().copied().collect();
    assert_eq!(
        keys,
        vec![
            ("item", "other"),
            ("item", "token_refused"),
            ("other", "token_refused"),
            ("playlist", "missing_token"),
        ]
    );
    let reason = window.reason();
    assert!(
        !reason.contains("script") && !reason.contains(".."),
        "{reason}"
    );
}

#[tokio::test]
async fn a_refused_token_is_counted_by_its_fixed_route_and_code() {
    let photos = photos().await;
    write_test_static_capsule(
        photos.dir.path(),
        DOCUMENTS_CAPSULE_ID,
        "viewer",
        "Test Documents viewer",
        "<!doctype html><title>Documents</title>",
    );
    let documents =
        app_token_for_authority(photos.dir.path(), DOCUMENTS_CAPSULE_ID, &photos.authority);
    for path in [item_route("0"), item_route("7"), PLAYLIST_ROUTE.to_string()] {
        let (status, _) = photos.get(&path, Some(&documents)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    flush_photos_unadmitted(photos.dir.path()).unwrap();
    // One event, or two if the requests straddled a window boundary.
    let events = unadmitted_events(photos.dir.path());
    assert!(matches!(events.len(), 1 | 2), "{events:?}");
    let mut totals = std::collections::BTreeMap::new();
    for event in &events {
        assert_eq!(event.principal_id, None);
        assert_eq!(event.result, "refused");
        let counts = event
            .reason
            .split(' ')
            .find_map(|part| part.strip_prefix("counts="))
            .unwrap();
        for entry in counts.split(',') {
            // Only fixed names: no position, no path from the request.
            let (key, count) = entry.rsplit_once(':').unwrap();
            assert!(
                ["item/token_refused", "playlist/token_refused"].contains(&key),
                "{}",
                event.reason
            );
            *totals.entry(key.to_string()).or_insert(0) += count.parse::<u32>().unwrap();
        }
    }
    assert_eq!(totals["item/token_refused"], 2);
    assert_eq!(totals["playlist/token_refused"], 1);
}

#[test]
fn refusals_before_the_token_leave_one_event_per_window() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path();
    let window = 1_800_000_000; // a window start: a multiple of 60
    for (route, code, at) in [
        ("item", "token_refused", window),
        ("item", "token_refused", window + 1),
        ("playlist", "missing_token", window + 30),
        ("item", "missing_token", window + 59),
    ] {
        count_photos_unadmitted_at(data_dir, route, code, at).unwrap();
    }
    assert!(
        unadmitted_events(data_dir).is_empty(),
        "the window is still open"
    );

    // The first request of a later window writes the finished one, once.
    count_photos_unadmitted_at(data_dir, "playlist", "token_refused", window + 60).unwrap();
    count_photos_unadmitted_at(data_dir, "playlist", "token_refused", window + 61).unwrap();
    let events = unadmitted_events(data_dir);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].reason,
        format!(
            "window={window}-{} counts=item/missing_token:1,item/token_refused:2,playlist/missing_token:1 overflow=0 total=4",
            window + 60
        )
    );

    // A clock that steps back counts into the open window.
    count_photos_unadmitted_at(data_dir, "item", "token_refused", window + 5).unwrap();
    // Shutdown writes the open window.
    flush_photos_unadmitted(data_dir).unwrap();
    flush_photos_unadmitted(data_dir).unwrap();
    let events = unadmitted_events(data_dir);
    assert_eq!(events.len(), 2);
    assert!(
        events[1]
            .reason
            .ends_with("counts=item/token_refused:1,playlist/token_refused:2 overflow=0 total=3"),
        "{}",
        events[1].reason
    );
    assert_ne!(events[0].event_id, events[1].event_id);
}

#[test]
fn past_the_key_cap_refusals_are_counted_as_overflow() {
    let mut window = PhotosUnadmittedWindow::new(0, 2);
    window.add("item", "token_refused");
    window.add("playlist", "token_refused");
    window.add("item", "missing_token");
    window.add("item", "missing_token");
    window.add("item", "token_refused");
    assert_eq!(window.counts.len(), 2);
    assert_eq!(window.counts[&("item", "token_refused")], 2);
    assert_eq!(window.overflow, 2);
    assert!(
        window.reason().ends_with("overflow=2 total=5"),
        "{}",
        window.reason()
    );

    // Counters saturate rather than wrap.
    window.counts.insert(("item", "token_refused"), u32::MAX);
    window.overflow = u32::MAX;
    window.add("item", "token_refused");
    window.add("item", "other");
    assert_eq!(window.counts[&("item", "token_refused")], u32::MAX);
    assert_eq!(window.overflow, u32::MAX);
    assert!(window.reason().ends_with(&format!("total={}", u32::MAX)));
}

// ---- The pin table is bounded ----

#[test]
fn a_full_pin_table_refuses_a_new_launch_and_keeps_live_pins() {
    assert_eq!(PHOTOS_MAX_PINS, 1024);
    let start = std::time::Instant::now();
    let mut pins = PhotosPins::new(3);
    for launch in ["a", "b", "c"] {
        pins.pin(launch, "sha-1", start).unwrap();
    }
    let refusal = pins.pin("d", "sha-1", start).unwrap_err();
    assert_eq!(refusal.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        refusal
            .reason
            .contains("too many Photos launches are open (3)"),
        "{}",
        refusal.reason
    );
    assert_eq!(pins.len(), 3, "no live pin was evicted");

    // The launches already pinned keep reading, and keep their pin.
    pins.pin("a", "sha-1", start).unwrap();
    assert_eq!(
        pins.pin("b", "sha-2", start).unwrap_err().status,
        StatusCode::CONFLICT
    );

    // Once the pins outlive a Photos token, a new launch has room again.
    let later = start + std::time::Duration::from_secs(PHOTOS_LAUNCH_TOKEN_TTL_SECS + 1);
    pins.pin("d", "sha-1", later).unwrap();
    assert_eq!(pins.len(), 1);
}
