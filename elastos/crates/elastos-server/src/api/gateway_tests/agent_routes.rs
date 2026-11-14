//! The owner's agent routes, driven through the gateway router.
//!
//! `off` runs in a build without the feature and `on` in a build with it.

use super::*;

const ENABLE: &str = "/api/apps/system/agents/enable";
const DISABLE: &str = "/api/apps/system/agents/disable";
const CREATE: &str = "/api/apps/system/agents/create";
const RETIRE: &str = "/api/apps/system/agents/retire";
const LIST: &str = "/api/apps/system/agents";

/// Sends one request and returns its status and body text.
async fn call(app: &Router, path: &str, token: &str, body: Option<Value>) -> (StatusCode, String) {
    let method = if path == LIST || path.ends_with("/summary") {
        "GET"
    } else {
        "POST"
    };
    let request = test_browser_request("localhost:61180", "null")
        .method(method)
        .uri(path)
        .header("x-elastos-home-token", token)
        .header(CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    answer(app.clone().oneshot(request).await.unwrap()).await
}

/// The status and body text of a response.
async fn answer(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn agent_file(data_dir: &std::path::Path) -> std::path::PathBuf {
    crate::auth::auth_state_path(data_dir)
        .unwrap()
        .with_file_name("agent-records.json")
}

fn audit_len(data_dir: &std::path::Path) -> usize {
    crate::auth::load_auth_state(data_dir).unwrap().audit.len()
}

/// An admin passkey owner with storage protection.
fn protected_owner(data_dir: &std::path::Path) -> TestPasskeyAuthority {
    let owner = passkey_authority(data_dir);
    crate::auth::store_test_principal_root_protection(data_dir, &owner.principal_id);
    owner
}

#[cfg(not(feature = "prototype-agents"))]
mod off {
    use super::*;

    #[tokio::test]
    async fn feature_off_has_no_agent_surface() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        let owner = protected_owner(dir.path());
        // A valid file with agents on and one agent: a build with the
        // feature serves it, so every refusal below is the feature's.
        let agent_id = crate::agents::tests::plant_enabled_home_with_one_agent(
            dir.path(),
            &owner.principal_id,
            &owner.proof_binding_id,
        );
        let written = std::fs::read(agent_file(dir.path())).unwrap();
        let events = audit_len(dir.path());

        let create = json!({"display_name": "Helper", "agent_host": "agent-host", "request_id": "request-2"});
        let routes = [
            (ENABLE, None),
            (DISABLE, None),
            (CREATE, Some(create)),
            (LIST, None),
            (RETIRE, Some(json!({ "agent_id": agent_id }))),
        ];
        for (path, body) in routes {
            assert_eq!(
                call(&app, path, &owner.system_token, body).await,
                (StatusCode::CONFLICT, crate::agents::FEATURE_OFF.to_string()),
                "{path}"
            );
        }
        assert_eq!(std::fs::read(agent_file(dir.path())).unwrap(), written);
        assert_eq!(audit_len(dir.path()), events);
    }
}

#[cfg(feature = "prototype-agents")]
mod on {
    use super::*;
    use crate::agent_admission::tests::{installed_agent_host, Signed, AGENT_HOST, AGENT_HOST_CID};

    /// A Home installed from a signed release that lists the Agent Host,
    /// with its gateway and its admin owner. The capsules a plain test
    /// state seeds go to a scratch folder: the signed release does not list
    /// them, and this Home holds only what its release installed.
    struct InstalledHome {
        home: crate::installed_release::tests::Fixture,
        state: GatewayState,
        app: Router,
        owner: TestPasskeyAuthority,
        _scratch: tempfile::TempDir,
    }

    fn installed_home() -> InstalledHome {
        let home = installed_agent_host(Signed::ByPublisher);
        let scratch = tempfile::tempdir().unwrap();
        let state = GatewayState {
            cache_dir: home.data.clone(),
            data_dir: home.data.clone(),
            ..test_state(scratch.path())
        };
        let owner = protected_owner(&home.data);
        if let Err(error) = crate::agent_admission::verify_agent_host(&home.data, AGENT_HOST) {
            panic!("the fixture's Agent Host is not admitted: {error:#}");
        }
        InstalledHome {
            home,
            app: gateway_router(state.clone()),
            state,
            owner,
            _scratch: scratch,
        }
    }

    fn create_body(request_id: &str) -> Value {
        json!({"display_name": "Helper", "agent_host": AGENT_HOST, "request_id": request_id})
    }

    fn conflict(reason: &str) -> (StatusCode, String) {
        (StatusCode::CONFLICT, reason.to_string())
    }

    fn admin_required() -> (StatusCode, String) {
        (StatusCode::FORBIDDEN, "admin passkey required".to_string())
    }

    #[tokio::test]
    async fn enable_needs_the_admin_passkey_owner() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        // A session with no passkey proof behind it, and a guest's passkey.
        let unproved = system_app_token(dir.path());
        let owner = protected_owner(dir.path());
        let guest = passkey_authority_with_name_role(
            dir.path(),
            Some("guest"),
            crate::auth::RuntimePrincipalRole::Guest,
        );
        for path in [ENABLE, DISABLE, LIST] {
            for token in [&unproved, &guest.system_token] {
                assert_eq!(
                    call(&app, path, token, None).await,
                    admin_required(),
                    "{path}"
                );
            }
        }
        for (path, body) in [
            (CREATE, create_body("request-1")),
            (
                RETIRE,
                json!({"agent_id": "agent:v2:0123456789abcdef0123456789abcdef"}),
            ),
        ] {
            for token in [&unproved, &guest.system_token] {
                let answer = call(&app, path, token, Some(body.clone())).await;
                assert_eq!(answer, admin_required(), "{path}");
            }
        }
        let no_token = call(&app, ENABLE, "", None).await;
        assert_eq!(no_token.0, StatusCode::FORBIDDEN, "{no_token:?}");
        assert!(!agent_file(dir.path()).exists(), "no refusal wrote a file");

        let enabled = call(&app, ENABLE, &owner.system_token, None).await;
        assert_eq!(enabled, (StatusCode::OK, r#"{"enabled":true}"#.to_string()));
        assert!(agent_file(dir.path()).exists());
    }

    #[tokio::test]
    async fn a_revoked_admin_is_refused_on_every_route() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        let owner = protected_owner(dir.path());
        let token = &owner.system_token;
        assert_eq!(call(&app, ENABLE, token, None).await.0, StatusCode::OK);
        let routes = [
            (ENABLE, None),
            (DISABLE, None),
            (CREATE, Some(create_body("request-1"))),
            (LIST, None),
            (
                RETIRE,
                Some(json!({"agent_id": "agent:v2:0123456789abcdef0123456789abcdef"})),
            ),
        ];
        // The passkey is revoked while its session is left open, so the
        // launch token passes and the revocation check alone refuses.
        let mut state = crate::auth::load_auth_state(dir.path()).unwrap();
        for principal in &mut state.principals {
            if principal.proof_binding_id == owner.proof_binding_id {
                principal.proof_binding.passkey.as_mut().unwrap().revoked_at = Some(now_ts());
            }
        }
        crate::auth::save_auth_state(dir.path(), &state, None).unwrap();
        let written = std::fs::read(agent_file(dir.path())).unwrap();
        let revoked = (
            StatusCode::INTERNAL_SERVER_ERROR,
            "passkey proof binding revoked".to_string(),
        );
        for (path, body) in routes.clone() {
            assert_eq!(call(&app, path, token, body).await, revoked, "{path}");
        }
        // Revoking through the store also ends the session.
        crate::auth::revoke_passkey_binding(dir.path(), &owner.proof_binding_id, now_ts()).unwrap();
        for (path, body) in routes {
            let answer = call(&app, path, token, body).await;
            assert_eq!(answer.0, StatusCode::FORBIDDEN, "{path}: {answer:?}");
        }
        assert_eq!(std::fs::read(agent_file(dir.path())).unwrap(), written);
    }

    #[tokio::test]
    async fn the_routes_refuse_until_the_owner_turns_agents_on() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        let owner = protected_owner(dir.path());
        let token = &owner.system_token;
        let off = conflict(crate::agents::NOT_ENABLED);
        assert_eq!(call(&app, LIST, token, None).await, off);
        assert_eq!(call(&app, CREATE, token, Some(create_body("r"))).await, off);
        let retire = json!({"agent_id": "agent:v2:0123456789abcdef0123456789abcdef"});
        assert_eq!(call(&app, RETIRE, token, Some(retire)).await, off);
        assert!(!agent_file(dir.path()).exists());
    }

    #[tokio::test]
    async fn an_owner_creates_lists_and_retires_an_agent() {
        let installed = installed_home();
        let (home, app) = (&installed.home, installed.app.clone());
        let token = &installed.owner.system_token;
        assert_eq!(call(&app, ENABLE, token, None).await.0, StatusCode::OK);

        let (status, body) = call(&app, CREATE, token, Some(create_body("request-1"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let created: Value = serde_json::from_str(&body).unwrap();
        let agent_id = created["agent_id"].as_str().unwrap().to_string();
        assert!(crate::auth::validate_agent_id(&agent_id).is_ok());
        assert_eq!(created["display_name"], "Helper");
        // The create response returns the exact package admission verified:
        // the release-signed name and registry CID, and the bundle CID the
        // Runtime's walk of the installed files gave. An agent launch binds
        // to those bytes.
        let stored_package = crate::agent_admission::verify_agent_host(&home.data, AGENT_HOST)
            .expect("the fixture's Agent Host is admitted")
            .package()
            .clone();
        assert_eq!(
            created["agent_host"],
            serde_json::to_value(stored_package).unwrap()
        );
        assert_eq!(created["retired_at"], Value::Null);

        // The same request again is the same agent.
        let (_, again) = call(&app, CREATE, token, Some(create_body("request-1"))).await;
        assert_eq!(serde_json::from_str::<Value>(&again).unwrap(), created);
        let (_, listed) = call(&app, LIST, token, None).await;
        let listed: Value = serde_json::from_str(&listed).unwrap();
        assert_eq!(listed, json!({ "agents": [created] }));

        // A body with a missing or unknown field, and an Agent Host the
        // signed release does not list.
        let written = std::fs::read(agent_file(&home.data)).unwrap();
        let mut owner_named = create_body("request-2");
        owner_named["owner"] = json!("person:local:someone");
        let mut no_request_id = create_body("request-2");
        no_request_id.as_object_mut().unwrap().remove("request_id");
        for body in [owner_named, no_request_id] {
            let (status, text) = call(&app, CREATE, token, Some(body)).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert!(text.starts_with("agent request is invalid: "), "{text}");
        }
        let mut unlisted = create_body("request-2");
        unlisted["agent_host"] = json!("other-host");
        assert_eq!(
            call(&app, CREATE, token, Some(unlisted)).await,
            conflict("agent host 'other-host' has no entry in the signed components record")
        );
        assert_eq!(std::fs::read(agent_file(&home.data)).unwrap(), written);

        let retire = json!({ "agent_id": agent_id });
        let (status, body) = call(&app, RETIRE, token, Some(retire.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let retired: Value = serde_json::from_str(&body).unwrap();
        assert!(retired["retired_at"].as_u64().is_some());
        assert_eq!(
            call(&app, RETIRE, token, Some(retire)).await,
            conflict("agent is already retired")
        );

        let disabled = call(&app, DISABLE, token, None).await;
        assert_eq!(
            disabled,
            (StatusCode::OK, r#"{"enabled":false}"#.to_string())
        );
        assert_eq!(
            call(&app, LIST, token, None).await,
            conflict(crate::agents::NOT_ENABLED)
        );
    }

    #[tokio::test]
    async fn a_child_runtime_refuses_create_and_the_home_itself_passes() {
        let installed = installed_home();
        let (home, app) = (&installed.home, installed.app.clone());
        let token = &installed.owner.system_token;
        // The Home itself: its sign-in store is its own data folder.
        assert_eq!(call(&app, ENABLE, token, None).await.0, StatusCode::OK);
        let (status, body) = call(&app, CREATE, token, Some(create_body("request-1"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let written = std::fs::read(agent_file(&home.data)).unwrap();

        // A child Runtime reads a sign-in store at another path than its own
        // data folder. Here that path is a link to this Home's own folder, so
        // the launch token and the owner check pass and the path rule alone
        // refuses. The gateway's front door cannot be driven as a child from
        // this test binary, so these rows call the route handlers themselves.
        let parent = tempfile::tempdir().unwrap();
        let other_path = parent.path().join("sign-in-store");
        std::os::unix::fs::symlink(&home.data, &other_path).unwrap();
        let _store = set_test_home_launch_auth_data_dir(&other_path);
        let state = || State(installed.state.clone());
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("localhost:61180"));
        headers.insert("origin", HeaderValue::from_static("null"));
        headers.insert("x-elastos-home-token", token.parse().unwrap());
        let not_the_home = conflict(crate::agent_admission::NOT_THE_HOME);
        let body = |value: Value| Bytes::from(value.to_string());

        let created = agents_create(state(), headers.clone(), body(create_body("request-2")));
        assert_eq!(answer(created.await).await, not_the_home);
        let enabled = agents_enable(state(), headers.clone());
        assert_eq!(answer(enabled.await).await, not_the_home);
        let disabled = agents_disable(state(), headers.clone());
        assert_eq!(answer(disabled.await).await, not_the_home);
        let listed = agents_list(state(), headers.clone());
        assert_eq!(answer(listed.await).await, not_the_home);
        let retired = agents_retire(state(), headers.clone(), body(json!({"agent_id": "a"})));
        assert_eq!(answer(retired.await).await, not_the_home);
        assert_eq!(std::fs::read(agent_file(&home.data)).unwrap(), written);
    }

    #[tokio::test]
    async fn a_refused_file_keeps_its_bytes_and_the_owner_still_signs_in() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        let owner = protected_owner(dir.path());
        let token = &owner.system_token;
        assert_eq!(call(&app, ENABLE, token, None).await.0, StatusCode::OK);

        // The file gains a field this Runtime does not write.
        let path = agent_file(dir.path());
        let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["pending"] = Value::Null;
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let planted = std::fs::read(&path).unwrap();
        let events = audit_len(dir.path());

        let unavailable = conflict(
            "agents are unavailable: agent file holds a field or value this Runtime does not write",
        );
        assert_eq!(
            call(&app, CREATE, token, Some(create_body("request-1"))).await,
            unavailable
        );
        for path in [ENABLE, DISABLE, LIST] {
            assert_eq!(call(&app, path, token, None).await, unavailable, "{path}");
        }
        let retire = json!({"agent_id": "agent:v2:0123456789abcdef0123456789abcdef"});
        assert_eq!(call(&app, RETIRE, token, Some(retire)).await, unavailable);
        assert_eq!(std::fs::read(&path).unwrap(), planted, "never rewritten");
        assert_eq!(audit_len(dir.path()), events);

        // The owner's own session, record and protection are as before.
        let summary = call(&app, "/api/apps/system/summary", token, None).await;
        assert_eq!(summary.0, StatusCode::OK, "{}", summary.1);
        let stored =
            crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id)
                .unwrap();
        assert_eq!(stored.principal_id, owner.principal_id);
        assert!(crate::auth::load_principal_root_protection(
            dir.path(),
            &stored.principal_id,
            &stored.localhost_root
        )
        .unwrap()
        .is_some());
    }
}
