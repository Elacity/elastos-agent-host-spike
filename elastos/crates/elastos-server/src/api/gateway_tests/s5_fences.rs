//! A5 S5 fence rows: routes 13, 14, 15, 16 and 19.
//!
//! Every route here takes no caller path, URI or object reference. The
//! Runtime builds the location from the launch token's resolved root. Each row
//! names the production line that builds it and shows that two launches'
//! locations differ.
//!
//! Routes 13-16 are Home-page routes. Their tokens come from a person's Home
//! launch, and each row also launches a stored agent of the same Home through
//! the production `launch_capsule` entry, from that Home's own data dir.
//! `launch_capsule` starts the capsule and returns
//! `LaunchResponse { id, name, status }` with no token (`api/routes.rs:157-161`),
//! and no code on the admitted start path stores a session grant
//! (`runtime.rs:348-361`, `agent_admission.rs`). The gateway accepts only Home
//! launch tokens (`gateway_home_token.rs:737-770`), which an agent launch
//! never receives. So an agent's guest has nothing to present: a route
//! request with no Home token is refused by the gateway's admission step
//! (`gateway_frontdoor.rs:276`) with `Gateway request requires an admitted
//! host and caller` (`gateway_frontdoor.rs:190`), and no file is written in
//! that Home. Each row therefore uses two people, P and Q, for the location
//! fence the S5 definition asks for: each signs in through
//! `auth::grant_passkey_session` (the production call a completed WebAuthn
//! ceremony ends in), and each app token is minted by the production Home
//! launch path. The same Home then adds the agent launch and its refusal.
//!
//! Route 13's app is not a Home target: the Home launch route maps the
//! `home-agent` bookmark to `assistant` (`gateway_home_runtime.rs:56-58`) and
//! hides it from the target list (`:360`, `:425`). Its row therefore calls the
//! same production mint the Home launch route uses
//! (`issue_home_projection_launch_token_with_context`, `gateway_home_runtime.rs:149`)
//! from the person's own sign-in context. `report-round5.md` gives the file:line
//! proof for this choice.

use super::*;
use serde_json::Value;

use crate::api::routes::tests::ProbeLaunch;
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
    /// This same Home's agent case: person P's stored agent, and the probe
    /// that launches it through the production `launch_capsule` entry over
    /// this Home's data dir. `None` when the build has no agents, where every
    /// agent launch is refused by `agents::require_build`.
    agent: Option<AgentHome>,
}

/// One stored agent of the Home and the probe that launches it in that Home.
struct AgentHome {
    probe: ProbeLaunch,
    id: String,
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
    // The same Home's agent case. Person P owns the stored agent, and the
    // probe launches it through `launch_capsule` over this Home's data dir.
    let agent = if crate::agents::require_build().is_ok() {
        let person = &people[0];
        let probe = ProbeLaunch::over_home(
            dir.path().to_path_buf(),
            &person.grant.principal_id,
            &person.grant.proof_binding_id,
            &person.grant.session_id,
            &person.context,
            &["s5-route-agent"],
        )
        .await;
        let id = probe.agents.first().expect("one stored agent").clone();
        Some(AgentHome { probe, id })
    } else {
        None
    };
    TwoPersonHome {
        dir,
        people: [p.clone(), q.clone()],
        agent,
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

fn root_object_path(dir: &std::path::Path, root: &str, relative: &str) -> std::path::PathBuf {
    elastos_common::localhost::rooted_localhost_fs_path(dir, &format!("{root}/{relative}")).unwrap()
}

fn object_path(home: &TwoPersonHome, root: &str, relative: &str) -> std::path::PathBuf {
    root_object_path(home.dir.path(), root, relative)
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

/// A route request with no `x-elastos-home-token`. That is everything an
/// agent launch can present: `launch_capsule` answers
/// `LaunchResponse { id, name, status }` (`api/routes.rs:157-161`) and the
/// admitted start stores no session grant (`runtime.rs:348-361`), while the
/// gateway accepts only Home launch tokens (`gateway_home_token.rs:737-770`).
fn agent_request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let builder = test_browser_request("localhost:61180", "null")
        .method(method)
        .uri(uri);
    match body {
        Some(body) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// Launches the Home's stored agent through the production `launch_capsule`
/// entry (`api/routes.rs:88`) in this same Home, with its capability requests
/// granted as a shell grants them. It shows the launch's answer carries no
/// token and that the admitted start stored no session grant for the agent,
/// then returns the agent's own route location under this Home.
async fn launch_stored_agent(home: &TwoPersonHome, relative: &str) -> std::path::PathBuf {
    let agent_home = home.agent.as_ref().expect("the agent case is built");
    let launched = agent_home
        .probe
        .launch_with_grants(&agent_home.id)
        .await
        .expect("the stored agent launches");
    let answer = serde_json::to_value(&launched.0).unwrap();
    assert_eq!(
        answer["status"], "completed",
        "the agent launch ran to its own answer"
    );
    let keys = answer
        .as_object()
        .expect("the launch answer is an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        ["id", "name", "status"],
        "an agent launch returns no token (`api/routes.rs:157-161`)"
    );
    let sessions = crate::auth::load_auth_state(&agent_home.probe.data_dir)
        .expect("the agent's Home reads")
        .sessions;
    assert!(
        sessions
            .iter()
            .all(|session| session.grant.principal_id != agent_home.id),
        "an admitted agent launch stores no session grant (`runtime.rs:348-361`)"
    );
    let agent_root = agent_home.probe.root(&agent_home.id);
    object_path(home, &agent_root, relative)
}

/// Presents what an agent launch really yields, nothing, to `uri`: a request
/// with no Home launch token. The gateway's admission step refuses it before
/// the handler runs: `require_gateway_launch_for` (`gateway_frontdoor.rs:276`)
/// requires a Home launch token, and an agent launch never receives one
/// (`gateway_home_token.rs:737-770`, `api/routes.rs:157-161`).
/// `gateway_frontdoor.rs:190` answers with the production literal. The route
/// writes no file in this same Home.
async fn assert_agent_launch_refused(
    app: axum::Router,
    uri: &str,
    method: &str,
    body: Value,
    agent_path: &std::path::Path,
    route: &str,
) {
    let refused = app
        .oneshot(agent_request(method, uri, Some(body)))
        .await
        .unwrap();
    let status = refused.status();
    let text = response_text_json(refused).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent's tokenless request is refused at {route}: {text}"
    );
    assert_eq!(
        text,
        json!("Gateway request requires an admitted host and caller"),
        "the gateway refuses an agent launch at {route}, which has no Home token"
    );
    assert!(
        !agent_path.exists(),
        "an agent launch writes no file in its Home at {route}"
    );
}

/// Route 13, and row 9. The location is
/// `gateway_home_agent.rs:79-84 home_agent_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/HomeAgent/workspace.json`
/// from the token's resolved root. Two people's launches get two different
/// locations, and the first person's document never reaches the second. Row
/// 9's fence is this fixed relative path plus the agent case: the request
/// carries no path field, a body that names one is refused, and a stored
/// agent of this same Home has no token this route accepts. An agent launch
/// returns `LaunchResponse { id, name, status }` and stores no session grant
/// (`api/routes.rs:157-161`, `runtime.rs:348-361`); a tokenless request is
/// refused by the gateway's admission step before the route's own token check
/// runs (`gateway_frontdoor.rs:276`, literal at `:190`) and writes nothing.
#[tokio::test]
async fn route_13_home_agent_workspace_refuses_an_agent_launch_and_two_people_get_two_locations() {
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

    let put_q = app.clone().oneshot(write(token_q, "q")).await.unwrap();
    assert_eq!(put_q.status(), StatusCode::OK);
    assert!(path_p.is_file(), "P's write landed under P's root");
    assert!(path_q.is_file(), "Q's write landed under Q's own root");

    // The agent case: the same Home's stored agent launches through
    // `launch_capsule` and gets no token, so its guest presents none. The
    // gateway refuses that tokenless request; the route writes nothing.
    if home.agent.is_some() {
        let agent_path = launch_stored_agent(&home, relative).await;
        assert_agent_launch_refused(
            app,
            "/api/apps/home-agent/workspace",
            "PUT",
            json!({
                "schema": "elastos.home-agent.workspace/v1",
                "if_revision": 0,
                "document": {"marker": "agent"}
            }),
            &agent_path,
            "route 13",
        )
        .await;
    }
}

/// Route 14. The location is `gateway_assistant.rs:134-139
/// assistant_workspace_uri`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace.json`.
/// The token is the one the person's Home launch produced for `assistant`.
/// Two people's launches get two different locations. A stored agent of the
/// same Home has no token for the route (`api/routes.rs:157-161`,
/// `runtime.rs:348-361`); a tokenless request is refused by the gateway's
/// admission step before the route's own token check runs
/// (`gateway_frontdoor.rs:276`, literal at `:190`) and writes nothing.
#[tokio::test]
async fn route_14_assistant_workspace_refuses_an_agent_launch_and_two_people_get_two_locations() {
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
        app.clone()
            .oneshot(app_request(
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

    // The agent case: the same Home's stored agent launches through
    // `launch_capsule` and gets no token, so its guest presents none. The
    // gateway refuses that tokenless request; the route writes nothing.
    if home.agent.is_some() {
        let agent_path = launch_stored_agent(&home, relative).await;
        assert_agent_launch_refused(
            app,
            "/api/apps/assistant/workspace",
            "PUT",
            json!({
                "schema": "elastos.assistant.workspace/v1",
                "if_revision": 0,
                "sessions": [],
                "draft": "agent"
            }),
            &agent_path,
            "route 14",
        )
        .await;
    }
}

/// Route 15. The location is
/// `gateway_assistant_workspace_v2.rs:96-106 object_location`, which builds
/// `{context.root().localhost_root()}/.AppData/ElastOS/Assistant/workspace-v2.json`.
/// The token is the one the person's Home launch produced for `assistant`.
/// Two people's launches get two different locations. A stored agent of the
/// same Home has no token for the route (`api/routes.rs:157-161`,
/// `runtime.rs:348-361`); a tokenless request is refused by the gateway's
/// admission step before the route's own token check runs
/// (`gateway_frontdoor.rs:276`, literal at `:190`) and writes nothing.
#[tokio::test]
async fn route_15_assistant_workspace_v2_refuses_an_agent_launch_and_two_people_get_two_locations()
{
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
        app.clone()
            .oneshot(write(token_q, "q", migration_q))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(path_p.is_file());
    assert!(path_q.is_file());

    // The agent case: the same Home's stored agent launches through
    // `launch_capsule` and gets no token, so its guest presents none. The
    // gateway refuses that tokenless request; the route writes nothing.
    if home.agent.is_some() {
        let agent_path = launch_stored_agent(&home, relative).await;
        assert_agent_launch_refused(
            app,
            "/api/apps/assistant/workspace-v2",
            "PUT",
            json!({
                "schema": "elastos.assistant.workspace/v2",
                "if_revision": 0,
                "document": {"marker": "agent"},
                "migration_revision": "agent"
            }),
            &agent_path,
            "route 15",
        )
        .await;
    }
}

/// Route 16. The location is `gateway_home_system.rs:6818-6820
/// home_browser_localhost_root` read by `:7033-7038 home_browser_state_uri`,
/// which builds `{context.root().localhost_root()}/.AppData/ElastOS/Home/browser-state.json`.
/// The token is the one the person's Home launch produced for the `home-gui`
/// shell, one of the three shell ids the route accepts (`:6453`).
/// Two people's launches get two different locations. A stored agent of the
/// same Home has no token for the route (`api/routes.rs:157-161`,
/// `runtime.rs:348-361`); a tokenless request is refused by the gateway's
/// admission step before the route's own token check runs
/// (`gateway_frontdoor.rs:276`, literal at `:190`) and writes nothing.
#[tokio::test]
async fn route_16_home_state_refuses_an_agent_launch_and_two_people_get_two_locations() {
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

    let response = app
        .clone()
        .oneshot(request("GET", &token_q, None))
        .await
        .unwrap();
    let status = response.status();
    let seen_q = response_text_json(response).await;
    assert_eq!(status, StatusCode::OK, "{seen_q}");
    assert_eq!(
        seen_q["layout"],
        Value::Null,
        "Q's launch reads its own state"
    );

    // The agent case: the same Home's stored agent launches through
    // `launch_capsule` and gets no token, so its guest presents none. The
    // gateway refuses that tokenless request; the route writes nothing.
    if home.agent.is_some() {
        let agent_path = launch_stored_agent(&home, relative).await;
        assert_agent_launch_refused(
            app,
            "/api/apps/home/state",
            "POST",
            json!({"layout": {"columns": 3}}),
            &agent_path,
            "route 16",
        )
        .await;
    }
}
