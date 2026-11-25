//! Owner recovery through the HTTP route keeps the agent file, the ids and
//! the roots, and the planted note still opens.

#![cfg(unix)]

use super::*;

#[tokio::test]
async fn owner_recovery_route_leaves_the_agent_file_and_ids() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let owner = passkey_authority_with_name(dir.path(), Some("owner"));
    let owner_principal =
        crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id).unwrap();
    crate::auth::store_test_principal_root_protection(dir.path(), &owner.principal_id);
    let planted = crate::agents::tests::plant_opening_agent(
        dir.path(),
        &owner.principal_id,
        "plant-recovery",
    );
    let protection = crate::auth::load_principal_root_protection(
        dir.path(),
        &owner.principal_id,
        &owner_principal.localhost_root,
    )
    .unwrap()
    .unwrap();
    let kit = crate::auth::recovery_kit_from_archive(
        dir.path(),
        protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    let agent_file = std::fs::read(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap();
    let note = std::fs::read(&planted.path).unwrap();

    let owner_passkey = owner_principal.proof_binding.passkey.as_ref().unwrap();
    let mut store = elastos_identity::IdentityStore::new(dir.path()).unwrap();
    store.load().unwrap();
    store.add_credential(elastos_identity::StoredCredential {
        credential_id: owner_passkey.credential_id.clone(),
        public_key: owner_passkey.public_key.clone(),
        sign_count: owner_passkey.sign_count,
        rp_id: owner_passkey.rp_id.clone(),
    });
    store.save().unwrap();

    let code =
        crate::auth::arm_owner_recovery(dir.path(), "http://localhost:61180", "localhost", 300)
            .unwrap();
    let request = |path: &str, body: Value| {
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost:61180")
            .header("origin", "http://localhost:61180")
            .header("x-elastos-owner-recovery", code.as_str())
            .header(CONTENT_TYPE, "application/json")
            .extension(axum::extract::ConnectInfo(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let begin = app
        .clone()
        .oneshot(request("/api/auth/owner-recovery/begin", json!({})))
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let begin: Value = serde_json::from_slice(
        &axum::body::to_bytes(begin.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let attestation = crate::auth::passkey_attestation_with_id_for_test(
        begin["options"]["publicKey"]["challenge"].as_str().unwrap(),
        "localhost",
        "http://localhost:61180",
        b"replacement-owner-passkey-same-id",
    );
    let complete = app
        .clone()
        .oneshot(request(
            "/api/auth/owner-recovery/complete",
            json!({
                "ceremony_id": begin["ceremony_id"],
                "response": attestation,
                "bundle": { "data_kit": kit }
            }),
        ))
        .await
        .unwrap();
    let status = complete.status();
    let body = axum::body::to_bytes(complete.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let complete: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(complete["principal_id"], owner.principal_id);

    let listed = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("GET")
                .uri("/api/apps/system/agents")
                .header(
                    "x-elastos-home-token",
                    complete["system_token"].as_str().unwrap(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed_status = listed.status();
    let listed_body = axum::body::to_bytes(listed.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        listed_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&listed_body)
    );
    let listed: Value = serde_json::from_slice(&listed_body).unwrap();
    assert_eq!(listed["agents"][0]["agent_id"], planted.agent_id);

    let after = std::fs::read(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap();
    assert_eq!(after, agent_file, "the agent file is byte-identical");
    let file: Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(
        file["agents"][0]["record"]["principal_id"],
        planted.agent_id
    );
    assert_eq!(file["agents"][0]["record"]["localhost_root"], planted.root);
    assert_eq!(std::fs::read(&planted.path).unwrap(), note);
    assert_eq!(
        crate::auth::read_principal_root_object(
            dir.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}

struct ImportedHome {
    temp: tempfile::TempDir,
    state: GatewayState,
    headers: HeaderMap,
    principal_id: String,
    localhost_root: String,
}

fn imported_home() -> ImportedHome {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path());
    let owner = passkey_authority(temp.path());
    let principal =
        crate::auth::load_principal_for_proof_binding(temp.path(), &owner.proof_binding_id)
            .unwrap();
    crate::auth::store_test_principal_root_protection(temp.path(), &owner.principal_id);
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", owner.home_token.parse().unwrap());
    headers.insert("host", "localhost:61180".parse().unwrap());
    headers.insert("origin", "http://localhost:61180".parse().unwrap());
    ImportedHome {
        temp,
        state,
        headers,
        principal_id: principal.principal_id,
        localhost_root: principal.localhost_root,
    }
}

fn different_root_key(home: &ImportedHome) -> elastos_runtime::auth::RecoveryKitV1 {
    let current = crate::auth::load_principal_root_protection(
        home.temp.path(),
        &home.principal_id,
        &home.localhost_root,
    )
    .unwrap()
    .unwrap();
    let replacement =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &home.principal_id);
    let kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        replacement.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    assert_ne!(kit.data_key_id, current.data_key_id);
    crate::auth::store_principal_root_protection(home.temp.path(), current).unwrap();
    kit
}

fn auth_bytes(dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(crate::auth::auth_state_path(dir).unwrap()).unwrap()
}

fn agent_bytes(dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(crate::agents::agent_file_path(dir).unwrap()).unwrap()
}

async fn import_kit(
    home: &ImportedHome,
    kit: elastos_runtime::auth::RecoveryKitV1,
    reassign: bool,
) -> anyhow::Result<crate::api::auth_gateway::RecoveryKitImportResponse> {
    crate::api::auth_gateway::recovery_kit_import_inner(
        &home.state,
        &home.headers,
        crate::api::auth_gateway::RecoveryKitMaterialImport {
            principal_id: home.principal_id.clone(),
            localhost_root: home.localhost_root.clone(),
            reassign_to_current_principal: reassign,
            kit,
            did_recovery_proof: None,
        },
    )
    .await
}

#[tokio::test]
async fn kit_import_refuses_a_different_root_key_when_agents_open() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-open",
    );
    let kit = different_root_key(&home);
    let auth = auth_bytes(home.temp.path());
    let agents = agent_bytes(home.temp.path());
    let note = std::fs::read(&planted.path).unwrap();
    let err = import_kit(&home, kit, false)
        .await
        .expect_err("a different root key must be refused while an agent's data opens")
        .to_string();
    assert_eq!(err, crate::agents::agents_would_stop_opening(1));
    assert_eq!(
        auth_bytes(home.temp.path()),
        auth,
        "the auth file is unchanged"
    );
    assert_eq!(
        agent_bytes(home.temp.path()),
        agents,
        "the agent file is unchanged"
    );
    assert_eq!(std::fs::read(&planted.path).unwrap(), note);
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}

#[tokio::test]
async fn opening_count_includes_an_agent_after_the_home_turns_agents_off() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-off",
    );
    let owner = crate::auth::stored_principal_record(home.temp.path(), &home.principal_id)
        .unwrap()
        .unwrap();
    let caller = crate::agents::Caller {
        principal_id: &home.principal_id,
        proof_binding_id: &owner.proof_binding_id,
        session_id: "session:off",
    };
    assert!(!crate::agents::set_enabled(home.temp.path(), &caller, false, 12).unwrap());
    assert_eq!(
        crate::agents::opening_agent_count(home.temp.path(), &home.principal_id).unwrap(),
        1,
        "turning agents off keeps the wrap, so the count still sees this agent"
    );
    let kit = different_root_key(&home);
    let auth = auth_bytes(home.temp.path());
    let agents = agent_bytes(home.temp.path());
    let err = import_kit(&home, kit, false)
        .await
        .expect_err("a different root key is refused while the wrap still opens")
        .to_string();
    assert_eq!(err, crate::agents::agents_would_stop_opening(1));
    assert_eq!(auth_bytes(home.temp.path()), auth);
    assert_eq!(agent_bytes(home.temp.path()), agents);
    assert!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .is_err(),
        "a public read stops while agents are off; the wrap is what the count opened"
    );
}

#[tokio::test]
async fn kit_import_allows_a_different_root_key_when_this_owner_has_no_agents() {
    let home = imported_home();
    let kit = different_root_key(&home);
    assert!(crate::agents::agent_file_path(home.temp.path())
        .unwrap()
        .symlink_metadata()
        .is_err());
    let response = import_kit(&home, kit.clone(), false)
        .await
        .expect("an owner with no agents still imports a Kit");
    assert_eq!(response.status, "imported");
    assert_eq!(response.principal_id, home.principal_id);
    let stored = crate::auth::load_principal_root_protection(
        home.temp.path(),
        &home.principal_id,
        &home.localhost_root,
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored.data_key_id, kit.data_key_id);
    assert!(crate::agents::agent_file_path(home.temp.path())
        .unwrap()
        .symlink_metadata()
        .is_err());
}

#[tokio::test]
async fn kit_import_allows_a_different_root_key_when_only_retired_agents_remain() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_retired_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-retired",
    );
    let kit = different_root_key(&home);
    let agents = agent_bytes(home.temp.path());
    let sealed = std::fs::read(&planted.path).unwrap();
    let response = import_kit(&home, kit.clone(), false)
        .await
        .expect("retired agents do not block the import");
    assert_eq!(response.status, "imported");
    assert_eq!(
        agent_bytes(home.temp.path()),
        agents,
        "the import does not re-wrap"
    );
    assert_eq!(std::fs::read(&planted.path).unwrap(), sealed);
    assert!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .is_err(),
        "a retired agent's note is data the owner already stopped using; it stays sealed under the key that wrapped it, and this import does not re-wrap it, so it does not open"
    );
    let stored = crate::auth::load_principal_root_protection(
        home.temp.path(),
        &home.principal_id,
        &home.localhost_root,
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored.data_key_id, kit.data_key_id);
    let file: Value = serde_json::from_slice(&agent_bytes(home.temp.path())).unwrap();
    assert_eq!(
        file["agents"][0]["record"]["principal_id"],
        planted.agent_id
    );
    assert_eq!(file["agents"][0]["record"]["localhost_root"], planted.root);
}

#[tokio::test]
async fn reassignment_refuses_when_the_replaced_account_owns_opening_agents() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-reassign",
    );
    let other = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Guest,
        "gateway-test-other-passkey",
    );
    let other_principal =
        crate::auth::load_principal_for_proof_binding(home.temp.path(), &other.proof_binding_id)
            .unwrap();
    let other_protection =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &other.principal_id);
    let kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        other_protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(kit.principal_id, other_principal.principal_id);
    let auth = auth_bytes(home.temp.path());
    let agents = agent_bytes(home.temp.path());
    let err = import_kit(&home, kit, true)
        .await
        .expect_err("reassignment must be refused before the commit")
        .to_string();
    assert_eq!(err, crate::agents::agents_would_belong_to_nobody(1));
    assert_eq!(auth_bytes(home.temp.path()), auth);
    assert_eq!(agent_bytes(home.temp.path()), agents);
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}

fn enable_agents(home: &ImportedHome) {
    let owner = crate::auth::stored_principal_record(home.temp.path(), &home.principal_id)
        .unwrap()
        .unwrap();
    let caller = crate::agents::Caller {
        principal_id: &home.principal_id,
        proof_binding_id: &owner.proof_binding_id,
        session_id: "session:race",
    };
    assert!(crate::agents::set_enabled(home.temp.path(), &caller, true, 1).unwrap());
}

fn create_racing_agent(
    home: &ImportedHome,
    request_id: &str,
) -> anyhow::Result<crate::agents::AgentView> {
    let owner = crate::auth::stored_principal_record(home.temp.path(), &home.principal_id)
        .unwrap()
        .unwrap();
    let caller = crate::agents::Caller {
        principal_id: &home.principal_id,
        proof_binding_id: &owner.proof_binding_id,
        session_id: "session:race",
    };
    crate::agents::create(
        home.temp.path(),
        &caller,
        &crate::agents::CreateRequest {
            display_name: "Helper".to_string(),
            agent_host: "agent-host".to_string(),
            request_id: request_id.to_string(),
        },
        |_| {
            Ok(
                crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                    "agent-host",
                    "bafyagenthost",
                    "bafyagenthostbytes",
                ),
            )
        },
        2,
    )
}

fn stored_key_id(home: &ImportedHome) -> String {
    crate::auth::load_principal_root_protection(
        home.temp.path(),
        &home.principal_id,
        &home.localhost_root,
    )
    .unwrap()
    .unwrap()
    .data_key_id
}

fn note_opens(dir: &std::path::Path, agent_id: &str) {
    let root = crate::auth::principal_stored_localhost_root(Some(dir), agent_id).unwrap();
    let uri = format!("{root}/journal/stable-id.txt");
    let path = elastos_common::localhost::rooted_localhost_fs_path(dir, &uri).unwrap();
    let note = b"opens-under-the-key-in-force";
    crate::auth::write_principal_root_object(dir, agent_id, &root, &uri, &path, note).unwrap();
    assert_eq!(
        crate::auth::read_principal_root_object(dir, agent_id, &root, &uri, &path).unwrap(),
        note,
        "the note opens under the key in force"
    );
}

/// Create and a root-key import at once. The import pauses before its store,
/// or create pauses before it reads the key. The other side then runs. The
/// import is refused and the key stays, or create runs after the store and
/// the note opens under the new key.
#[tokio::test]
async fn create_and_a_root_key_import_at_once_do_not_seal_the_new_agent() {
    race_root_key_import(true);
    race_root_key_import(false);
}

fn wait_for_the_pause(done: &std::sync::mpsc::Receiver<String>) {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(30) {
        if crate::agents::agent_writer_pause_arrived() {
            return;
        }
        match done.try_recv() {
            Ok(message) => panic!("finished before the pause: {message}"),
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("the pausing side ended before the pause");
            }
        }
    }
    panic!("agent writer did not pause");
}

fn still_running<T>(handle: &std::thread::ScopedJoinHandle<'_, T>) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(5) {
        if handle.is_finished() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    !handle.is_finished()
}

fn drive<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("race runtime")
        .block_on(future)
}

fn race_root_key_import(import_first: bool) {
    let home = imported_home();
    enable_agents(&home);
    let kit = different_root_key(&home);
    let new_key = kit.data_key_id.clone();
    let old_key = stored_key_id(&home);
    assert_ne!(old_key, new_key);
    let point = if import_first {
        crate::agents::PAUSE_BEFORE_STORE
    } else {
        crate::agents::PAUSE_BEFORE_WRAP
    };
    let home_ref = &home;
    let (import_result, created) = std::thread::scope(|scope| {
        let pause = crate::agents::arm_agent_writer_pause(home_ref.temp.path(), point);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if import_first {
            let tx = done_tx.clone();
            let import = scope.spawn(move || {
                let result = drive(import_kit(home_ref, kit, false));
                let _ = tx.send(format!("{result:?}"));
                result
            });
            wait_for_the_pause(&done_rx);
            let create = scope.spawn(move || create_racing_agent(home_ref, "race-import-first"));
            assert!(
                still_running(&create),
                "create sealed an agent before the import stored the key"
            );
            drop(pause);
            let import_result = import.join().unwrap();
            let created = create.join().unwrap();
            (import_result, created)
        } else {
            let tx = done_tx.clone();
            let create = scope.spawn(move || {
                let result = create_racing_agent(home_ref, "race-create-first");
                let _ = tx.send(format!("{result:?}"));
                result
            });
            wait_for_the_pause(&done_rx);
            let import = scope.spawn(move || drive(import_kit(home_ref, kit, false)));
            assert!(
                still_running(&import),
                "the import stored the key while create held the writer"
            );
            drop(pause);
            let created = create.join().unwrap();
            let import_result = import.join().unwrap();
            (import_result, created)
        }
    });
    let created = created.expect("create");
    if import_first {
        let response = import_result.expect("the import stores the new key, then create runs");
        assert_eq!(response.status, "imported");
        assert_eq!(stored_key_id(&home), new_key);
    } else {
        let err = import_result
            .expect_err("the import is refused and the key stays")
            .to_string();
        assert_eq!(err, crate::agents::agents_would_stop_opening(1));
        assert_eq!(stored_key_id(&home), old_key);
        assert!(
            crate::auth::load_auth_state(home.temp.path())
                .unwrap()
                .audit
                .iter()
                .all(|event| event.event_type != "auth.recovery_kit.imported"),
            "a refused import writes no imported event"
        );
    }
    note_opens(home.temp.path(), &created.agent_id);
}

fn agent_owner(dir: &std::path::Path) -> String {
    let file: Value = serde_json::from_slice(&agent_bytes(dir)).unwrap();
    file["agents"][0]["record"]["owner"]
        .as_str()
        .unwrap()
        .to_string()
}

fn kit_holding(
    dir: &std::path::Path,
    principal_id: &str,
    root: &str,
) -> elastos_runtime::auth::RecoveryKitV1 {
    let stored = crate::auth::load_principal_root_protection(dir, principal_id, root)
        .unwrap()
        .unwrap();
    let kit =
        crate::auth::recovery_kit_from_archive(dir, stored.protectors[0].archive.as_ref().unwrap())
            .unwrap();
    assert_eq!(kit.principal_id, principal_id);
    assert_eq!(kit.data_key_id, stored.data_key_id);
    kit
}

#[tokio::test]
async fn reassignment_allows_when_the_owner_id_and_the_key_stay() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-same-id",
    );
    let key_before = stored_key_id(&home);
    let kit = kit_holding(home.temp.path(), &home.principal_id, &home.localhost_root);
    let response = import_kit(&home, kit, true)
        .await
        .expect("the owner id stays and the key still opens the note");
    assert_eq!(response.status, "reassigned");
    assert_eq!(response.principal_id, home.principal_id);
    assert_eq!(agent_owner(home.temp.path()), home.principal_id);
    assert_eq!(stored_key_id(&home), key_before);
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}

#[tokio::test]
async fn reassignment_allows_when_the_recovered_owner_keeps_the_agents() {
    let home = imported_home();
    let other = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Admin,
        "gateway-test-recovered-owner",
    );
    let other_principal =
        crate::auth::load_principal_for_proof_binding(home.temp.path(), &other.proof_binding_id)
            .unwrap();
    let other_protection =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &other.principal_id);
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &other.principal_id,
        "plant-kept",
    );
    let kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        other_protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(kit.principal_id, other_principal.principal_id);
    assert_eq!(kit.data_key_id, other_protection.data_key_id);
    assert_ne!(kit.principal_id, home.principal_id);
    let response = import_kit(&home, kit, true)
        .await
        .expect("these agents name the recovered owner, and the Kit holds that key");
    assert_eq!(response.status, "reassigned");
    assert_eq!(response.principal_id, other.principal_id);
    assert_eq!(agent_owner(home.temp.path()), other.principal_id);
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}

#[tokio::test]
async fn reassignment_refuses_a_retired_agent_that_would_belong_to_nobody() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_retired_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-retired-owner",
    );
    let other = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Guest,
        "gateway-test-retired-reassign",
    );
    let other_protection =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &other.principal_id);
    let kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        other_protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    let auth = auth_bytes(home.temp.path());
    let agents = agent_bytes(home.temp.path());
    let err = import_kit(&home, kit, true)
        .await
        .expect_err("a retired record still names the owner id this recovery changes")
        .to_string();
    assert_eq!(err, crate::agents::agents_would_belong_to_nobody(1));
    assert_eq!(auth_bytes(home.temp.path()), auth);
    assert_eq!(agent_bytes(home.temp.path()), agents);
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.temp.path(),
            &planted.agent_id,
            &planted.root,
            &planted.uri,
            &planted.path
        )
        .unwrap(),
        planted.note,
        "the note still opens"
    );
}
