//! A5 S5 fence rows: routes 13, 14, 15, 16 and 19.
//!
//! Every route here takes no caller path, URI or object reference. The
//! Runtime builds the location from the launch token's resolved root. Each row
//! names the production line that builds it and shows that two launches'
//! locations differ.
//!
//! Routes 13-16 are Home-page routes, and their tokens come only from a
//! person's Home launch. `launch_capsule` starts the capsule and returns
//! `LaunchResponse { id, name, status }` with no token (`api/routes.rs:157-161`),
//! and no code on the admitted start path mints an app token or stores a
//! session grant (`runtime.rs:348-361`, `agent_admission.rs`). The Home launch
//! route needs a `home` token from a person (`gateway_home_runtime.rs:46`) and
//! mints the app token from that person's context (`:149`). So, as the S5
//! definition allows for a person-only route, each row here uses two people,
//! P and Q: each signs in through `auth::grant_passkey_session` (the production
//! call a completed WebAuthn ceremony ends in), and each app token is minted by
//! the production Home launch path.
//!
//! Route 13's app is not a Home target: the Home launch route maps the
//! `home-agent` bookmark to `assistant` (`gateway_home_runtime.rs:56-58`) and
//! hides it from the target list (`:360`, `:425`). Its row therefore calls the
//! same production mint the Home launch route uses
//! (`issue_home_projection_launch_token_with_context`, `gateway_home_runtime.rs:149`)
//! from the person's own sign-in context. `report-round4.md` gives the file:line
//! proof for this choice.

use super::*;
use serde_json::Value;

use crate::auth::{PasskeySessionPurpose, PasskeySessionRequest, ResolvedPrincipalRoot};

const RP_ID: &str = "elastos.elacitylabs.com";
const ORIGIN: &str = "https://elastos.elacitylabs.com";

/// A Home with two people who each signed in. Each person has a passkey
/// record, a protected root and an active session grant, all made by the
/// production enrollment and sign-in calls. The fixed root that the location
/// plants pin to also holds a protection here, so a plant reaches the row's
/// own separate-location assertion instead of stopping at a missing
/// protection.
struct TwoPersonHome {
    dir: tempfile::TempDir,
    people: [Person; 2],
}

#[derive(Clone)]
struct Person {
    context: HomeLaunchTokenContext,
    root: String,
    grant: AuthSessionGrantV1,
}

async fn two_person_home() -> TwoPersonHome {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut people = Vec::new();
    for credential in ["s5-person-p", "s5-person-q"] {
        let now = crate::auth::now_ts();
        let public_key = format!("{credential}-public-key");
        let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
            credential_id: credential.to_string(),
            public_key: public_key.clone(),
            sign_count: 1,
            user_verified: true,
            origin: ORIGIN.to_string(),
            rp_id: RP_ID.to_string(),
            created_at: now,
            last_used_at: now,
            revoked_at: None,
        });
        let principal_id = crate::auth::passkey_credential_principal_id(RP_ID, credential).unwrap();
        let record = crate::auth::upsert_principal_for_binding_as_role_named(
            dir.path(),
            binding,
            principal_id,
            crate::auth::RuntimePrincipalRole::Admin,
            Some(credential),
            now,
        )
        .unwrap();
        crate::auth::store_test_principal_root_protection(dir.path(), &record.principal_id);
        // A completed passkey sign-in ends in this production call, which
        // stores the session grant the Home token is bound to.
        let grant = crate::auth::grant_passkey_session(
            dir.path(),
            PasskeySessionRequest {
                credential: &elastos_identity::StoredCredential {
                    credential_id: credential.to_string(),
                    public_key: public_key.clone(),
                    sign_count: 2,
                    rp_id: RP_ID.to_string(),
                },
                origin: ORIGIN,
                user_verified: true,
                display_name: None,
                profile_display_name: None,
                reason: "s5 fence person sign-in",
                purpose: PasskeySessionPurpose::SignIn,
            },
        )
        .unwrap();
        let root = ResolvedPrincipalRoot::resolve(dir.path(), dir.path(), &record.principal_id)
            .expect("the stored person has a root");
        let root_name = root.localhost_root().to_string();
        let context = HomeLaunchTokenContext::resolved(
            root,
            grant.session_id.clone(),
            Some(grant.proof_binding_id.clone()),
            grant.grant_id.clone(),
        );
        people.push(Person {
            context,
            root: root_name,
            grant,
        });
    }
    let [p, q] = people.as_slice() else {
        panic!("two people");
    };
    // The plants pin every route's location to this fixed principal and root.
    // Both hold a current protection here, so a planted row reads and writes
    // the shared location and fails on its separate-location assertion.
    crate::auth::valid_agent::plant(dir.path());
    crate::auth::store_test_principal_root_protection_for(
        dir.path(),
        crate::auth::valid_agent::ID,
        crate::auth::valid_agent::ROOT,
    );
    TwoPersonHome {
        dir,
        people: [p.clone(), q.clone()],
    }
}

/// The person's Home token, minted by the production call
/// `/api/auth/session/refresh` makes (`auth_gateway.rs:3637`).
fn home_token(home: &TwoPersonHome, person: usize) -> String {
    issue_home_launch_token_for_auth_grant(
        home.dir.path(),
        HOME_CAPSULE_ID,
        &home.people[person].grant,
    )
    .expect("the person's Home token")
}

/// The app token one person's Home launch produces: the production handler,
/// with the person's Home token, returns it in the route fragment.
async fn launched_token(
    home: &TwoPersonHome,
    state: &GatewayState,
    person: usize,
    target: &str,
) -> String {
    let request = test_browser_request("localhost:61180", "http://localhost:61180")
        .header("x-elastos-home-token", home_token(home, person))
        .body(Body::empty())
        .unwrap();
    let Json(launch) = home_launch(
        State(state.clone()),
        request.headers().clone(),
        Json(HomeLaunchRequest {
            target: target.to_string(),
            query: BTreeMap::new(),
        }),
        &crate::setup::detect_platform(),
    )
    .await
    .unwrap_or_else(|(status, error)| {
        panic!(
            "Home launch of {target} failed: {status} {}",
            error.0["error"]
        )
    });
    let route = url::Url::parse(&format!("http://localhost:61180{}", launch.route)).unwrap();
    form_urlencoded::parse(route.fragment().unwrap().as_bytes())
        .find(|(key, _)| key == "home_token")
        .expect("the launch route carries its token")
        .1
        .into_owned()
}

/// A Home target the Runtime launches as a projection, so the launch needs no
/// Runtime process. This is the same staging the Browser launch rows use.
fn make_web_projection(dir: &std::path::Path, target: &str) {
    let path = dir.join("capsules").join(target).join("capsule.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the seeded capsule")).unwrap();
    manifest["type"] = json!("web-projection");
    manifest["runtime_abi"] = json!("elastos.runtime-projection/v1");
    manifest["bus_contract"] = json!("elastos.runtime-projection/v1");
    manifest["execution"] = json!("web-projection");
    manifest["projections"] = json!(["web"]);
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn app_token(home: &TwoPersonHome, person: usize, app: &str) -> String {
    issue_home_projection_launch_token_with_context(
        home.dir.path(),
        app,
        app,
        &home.people[person].context,
    )
    .expect("the person's app token")
}

fn object_path(home: &TwoPersonHome, root: &str, relative: &str) -> std::path::PathBuf {
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

/// A route answer that may be JSON or a bare refusal text, for an assert
/// message: JSON when it parses, otherwise the text.
async fn response_text_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
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
/// from the token's resolved root. The route is person-only: no agent launch
/// mints a `home-agent` token, and the Home target normalization at
/// `gateway_home_runtime.rs:56-58` sends the `home-agent` bookmark to
/// `assistant`. Two people's launches get two different locations, and the
/// first person's document never reaches the second. Row 9's fence is this
/// person-only reach plus the route's fixed relative path: the request carries
/// no path field, and a body that names one is refused.
#[tokio::test]
async fn route_13_home_agent_workspace_is_person_only_and_two_people_get_two_locations() {
    let home = two_person_home().await;
    let app = gateway_router(test_state(home.dir.path()));
    let token_p = app_token(&home, 0, "home-agent");
    let token_q = app_token(&home, 1, "home-agent");
    let (root_p, root_q) = (home.people[0].root.clone(), home.people[1].root.clone());
    let relative = ".AppData/ElastOS/HomeAgent/workspace.json";
    let path_p = object_path(&home, &root_p, relative);
    let path_q = object_path(&home, &root_q, relative);
    assert_ne!(path_p, path_q, "two launches, two locations");

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
    let put_p = app
        .clone()
        .oneshot(write(token_p.clone(), "p"))
        .await
        .unwrap();
    assert_eq!(put_p.status(), StatusCode::OK);

    // The row's own separate-location assertion: Q's launch reads its own
    // empty workspace, never P's document.
    let get_q = app
        .clone()
        .oneshot(app_request(
            "GET",
            "/api/apps/home-agent/workspace",
            &token_q,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(get_q.status(), StatusCode::OK);
    let seen_by_q = response_json(get_q).await;
    assert_eq!(
        seen_by_q["revision"], 0,
        "Q's launch reads its own empty workspace"
    );
    assert_eq!(
        seen_by_q["document"],
        json!({}),
        "Q's launch reads its own empty workspace"
    );

    let seen_by_p = response_json(
        app.clone()
            .oneshot(app_request(
                "GET",
                "/api/apps/home-agent/workspace",
                &token_p,
                None,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        seen_by_p["document"],
        json!({"marker": "p"}),
        "P's launch reads its own document"
    );

    // No request field can name another location.
    let named = app
        .clone()
        .oneshot(app_request(
            "PUT",
            "/api/apps/home-agent/workspace",
            &token_q,
            Some(json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {},
                "path": format!("{root_p}/{relative}")
            })),
        ))
        .await
        .unwrap();
    assert!(
        named.status().is_client_error(),
        "a caller path is refused: {}",
        named.status()
    );
    assert!(!path_q.exists());

    let put_q = app.oneshot(write(token_q, "q")).await.unwrap();
    assert_eq!(put_q.status(), StatusCode::OK);
    assert!(path_p.is_file(), "P's write landed under P's root");
    assert!(path_q.is_file(), "Q's write landed under Q's own root");
}

/// Route 14. The location is `gateway_assistant.rs:134-139
/// assistant_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace.json`.
/// The token is the one the person's Home launch produced for `assistant`.
/// Two people's launches get two different locations.
#[tokio::test]
async fn route_14_assistant_workspace_is_person_only_and_two_people_get_two_locations() {
    let home = two_person_home().await;
    let state = test_state(home.dir.path());
    make_web_projection(home.dir.path(), "assistant");
    let app = gateway_router(state.clone());
    let token_p = launched_token(&home, &state, 0, "assistant").await;
    let token_q = launched_token(&home, &state, 1, "assistant").await;
    let (root_p, root_q) = (home.people[0].root.clone(), home.people[1].root.clone());
    let relative = ".AppData/ElastOS/Assistant/workspace.json";
    let path_p = object_path(&home, &root_p, relative);
    let path_q = object_path(&home, &root_q, relative);
    assert_ne!(path_p, path_q, "two launches, two locations");

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
            .oneshot(write(token_p.clone(), "p"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The row's own separate-location assertion: Q's launch reads its own
    // empty workspace, never P's draft.
    let seen_by_q = app
        .clone()
        .oneshot(app_request(
            "GET",
            "/api/apps/assistant/workspace",
            &token_q,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(seen_by_q.status(), StatusCode::OK);
    assert_eq!(
        response_json(seen_by_q).await,
        json!({
            "schema": "elastos.assistant.workspace/v1",
            "revision": 0,
            "sessions": [],
            "draft": ""
        }),
        "Q's launch reads its own empty workspace"
    );

    assert_eq!(
        app.clone()
            .oneshot(write(token_q.clone(), "q"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let seen_by_p = response_json(
        app.oneshot(app_request(
            "GET",
            "/api/apps/assistant/workspace",
            &token_p,
            None,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(seen_by_p["draft"], "p", "P's launch reads its own draft");
    assert!(path_p.is_file());
    assert!(path_q.is_file());
}

/// Route 15. The location is
/// `gateway_assistant_workspace_v2.rs:96-106 object_location`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace-v2.json`.
/// The token is the one the person's Home launch produced for `assistant`.
/// Two people's launches get two different locations.
#[tokio::test]
async fn route_15_assistant_workspace_v2_is_person_only_and_two_people_get_two_locations() {
    let home = two_person_home().await;
    let state = test_state(home.dir.path());
    make_web_projection(home.dir.path(), "assistant");
    let app = gateway_router(state.clone());
    let token_p = launched_token(&home, &state, 0, "assistant").await;
    let token_q = launched_token(&home, &state, 1, "assistant").await;
    let (root_p, root_q) = (home.people[0].root.clone(), home.people[1].root.clone());
    let relative = ".AppData/ElastOS/Assistant/workspace-v2.json";
    let path_p = object_path(&home, &root_p, relative);
    let path_q = object_path(&home, &root_q, relative);
    assert_ne!(path_p, path_q, "two launches, two locations");

    // The first v2 save names the retained sources it read, as the client's
    // own GET returns them.
    let read_first =
        |token: String| app_request("GET", "/api/apps/assistant/workspace-v2", &token, None);
    let seen_p = app
        .clone()
        .oneshot(read_first(token_p.clone()))
        .await
        .unwrap();
    assert_eq!(seen_p.status(), StatusCode::OK);
    let seen_p = response_json(seen_p).await;
    assert_eq!(seen_p["revision"], 0);
    assert_eq!(seen_p["document"], json!({}));
    let migration_p = seen_p["migration_revision"]
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
            .oneshot(write(token_p, "p", migration_p))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The row's own separate-location assertion: Q's launch reads its own
    // empty document, never P's.
    let seen = app
        .clone()
        .oneshot(read_first(token_q.clone()))
        .await
        .unwrap();
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = response_json(seen).await;
    assert_eq!(
        seen["revision"], 0,
        "Q's launch reads its own empty workspace"
    );
    assert_eq!(
        seen["document"],
        json!({}),
        "Q's launch reads its own empty workspace"
    );
    let migration_q = seen["migration_revision"]
        .as_str()
        .expect("the first save names its retained sources")
        .to_string();

    assert_eq!(
        app.oneshot(write(token_q, "q", migration_q))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(path_p.is_file());
    assert!(path_q.is_file());
}

/// Route 16. The location is `gateway_home_system.rs:6818-6820
/// home_browser_localhost_root` read by `:7033-7038 home_browser_state_uri`,
/// which builds `{context.root().localhost_root()}/.AppData/ElastOS/Home/browser-state.json`.
/// The token is the one the person's Home launch produced for the `home-gui`
/// shell, one of the three shell ids the route accepts (`:6453`).
/// Two people's launches get two different locations.
#[tokio::test]
async fn route_16_home_state_is_person_only_and_two_people_get_two_locations() {
    let home = two_person_home().await;
    let state = test_state(home.dir.path());
    make_web_projection(home.dir.path(), "home-gui");
    let app = gateway_router(state.clone());
    let token_p = launched_token(&home, &state, 0, "home-gui").await;
    let token_q = launched_token(&home, &state, 1, "home-gui").await;
    let (root_p, root_q) = (home.people[0].root.clone(), home.people[1].root.clone());
    let relative = ".AppData/ElastOS/Home/browser-state.json";
    let path_p = object_path(&home, &root_p, relative);
    let path_q = object_path(&home, &root_q, relative);
    assert_ne!(path_p, path_q, "two launches, two locations");

    // A shell page's token carries the opaque capsule origin, as
    // `require_capsule_browser_origin` requires.
    let request = |method: &str, token: &str, body: Option<Value>| {
        let builder = test_browser_request("localhost:61180", "null")
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
    let response = app
        .clone()
        .oneshot(request("GET", &token_p, None))
        .await
        .unwrap();
    let status = response.status();
    let seen_p = response_text_json(response).await;
    assert_eq!(status, StatusCode::OK, "{seen_p}");
    assert_eq!(
        seen_p["localhost_root"], root_p,
        "each launch's state is under its own root"
    );

    let response = app
        .clone()
        .oneshot(request("GET", &token_q, None))
        .await
        .unwrap();
    let status = response.status();
    let seen_q = response_text_json(response).await;
    assert_eq!(status, StatusCode::OK, "{seen_q}");
    assert_eq!(
        seen_q["localhost_root"], root_q,
        "each launch's state is under its own root"
    );

    let written = app
        .clone()
        .oneshot(request(
            "POST",
            &token_p,
            Some(json!({"layout": {"columns": 3}})),
        ))
        .await
        .unwrap();
    assert_eq!(written.status(), StatusCode::OK);
    assert!(path_p.is_file());
    assert!(!path_q.exists());

    let response = app.oneshot(request("GET", &token_q, None)).await.unwrap();
    let status = response.status();
    let seen_q = response_text_json(response).await;
    assert_eq!(status, StatusCode::OK, "{seen_q}");
    assert_eq!(
        seen_q["layout"],
        Value::Null,
        "Q's launch reads its own state"
    );
}
