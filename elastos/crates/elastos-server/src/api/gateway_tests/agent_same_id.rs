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

/// The whole data root, before and after. The key store leaves its own
/// lifecycle lock. The agents file and its lock stay absent.
fn assert_person_without_agents_leaves_no_agent_file(before: &[String], after: &[String]) {
    let added: Vec<_> = after
        .iter()
        .filter(|entry| !before.contains(entry))
        .cloned()
        .collect();
    let removed: Vec<_> = before
        .iter()
        .filter(|entry| !after.contains(entry))
        .cloned()
        .collect();
    assert!(removed.is_empty(), "the import removed {removed:?}");
    assert!(
        added
            .iter()
            .all(|entry| entry == "ElastOS/System/Auth/principal-root-lifecycle.lock"),
        "the whole data root gained {added:?}"
    );
    assert!(
        after.iter().all(|entry| {
            !entry.ends_with("agent-records.json") && !entry.ends_with("agent-records.json.lock")
        }),
        "a person without agents leaves no agents file"
    );
}

fn data_root_entries(root: &std::path::Path) -> Vec<String> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            entries.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    entries.sort();
    entries
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
    let before = data_root_entries(home.temp.path());
    let response = import_kit(&home, kit.clone(), false)
        .await
        .expect("an owner with no agents still imports a Kit");
    assert_eq!(response.status, "imported");
    assert_person_without_agents_leaves_no_agent_file(
        &before,
        &data_root_entries(home.temp.path()),
    );
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

fn wait_for_the_pause(data_dir: &std::path::Path, done: &std::sync::mpsc::Receiver<String>) {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(30) {
        if crate::agents::agent_writer_pause_arrived(data_dir) {
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

/// Both waiters in one five-second window. A second call would start another
/// window and let a slow machine time the first waiter out before the second
/// is checked.
fn both_stay_through_one_window<T, U>(
    left: &std::thread::ScopedJoinHandle<'_, T>,
    right: &std::thread::ScopedJoinHandle<'_, U>,
    left_reason: &str,
    right_reason: &str,
) {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(5) {
        assert!(!left.is_finished(), "{left_reason}");
        assert!(!right.is_finished(), "{right_reason}");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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
            wait_for_the_pause(home_ref.temp.path(), &done_rx);
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
            wait_for_the_pause(home_ref.temp.path(), &done_rx);
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

/// Two imports at once. One kit holds the key in force. It takes the writer
/// while the other import holds that writer, and the decision under the lock
/// refuses the kit that would replace the key.
#[tokio::test]
async fn two_imports_at_once_one_holds_the_key_in_force() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-two-imports",
    );
    let different = different_root_key(&home);
    let same = kit_holding(home.temp.path(), &home.principal_id, &home.localhost_root);
    let old_key = stored_key_id(&home);
    assert_eq!(same.data_key_id, old_key);
    assert_ne!(different.data_key_id, old_key);
    let home_ref = &home;
    let (different_result, same_result) = std::thread::scope(|scope| {
        let pause = crate::agents::arm_agent_writer_pause(
            home_ref.temp.path(),
            crate::agents::PAUSE_BEFORE_STORE,
        );
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let tx = done_tx.clone();
        let different_import = scope.spawn(move || {
            let result = drive(import_kit(home_ref, different, false));
            let _ = tx.send(format!("{result:?}"));
            result
        });
        wait_for_the_pause(home_ref.temp.path(), &done_rx);
        let same_import = scope.spawn(move || drive(import_kit(home_ref, same, false)));
        assert!(
            still_running(&same_import),
            "the import that holds the key in force did not take the writer"
        );
        drop(pause);
        let different_result = different_import.join().unwrap();
        let same_result = same_import.join().unwrap();
        (different_result, same_result)
    });
    assert_eq!(
        different_result
            .expect_err("the other kit changes the key while an agent opens")
            .to_string(),
        crate::agents::agents_would_stop_opening(1)
    );
    let response = same_result.expect("the kit that holds the key in force is stored");
    assert_eq!(response.status, "imported");
    assert_eq!(stored_key_id(&home), old_key);
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
        "the note still opens under the key in force"
    );
}

/// Two imports and a create, at both pauses. The same-key import still holds
/// the writer. The other import and the create wait, and the new agent's
/// note opens under whichever key the store left.
#[tokio::test]
async fn two_imports_and_a_create_do_not_seal_the_new_agent() {
    two_imports_and_a_create(true);
    two_imports_and_a_create(false);
}

fn two_imports_and_a_create(import_pauses: bool) {
    let home = imported_home();
    enable_agents(&home);
    let different = different_root_key(&home);
    let same = kit_holding(home.temp.path(), &home.principal_id, &home.localhost_root);
    let old_key = stored_key_id(&home);
    assert_eq!(same.data_key_id, old_key);
    assert_ne!(different.data_key_id, old_key);
    let point = if import_pauses {
        crate::agents::PAUSE_BEFORE_STORE
    } else {
        crate::agents::PAUSE_BEFORE_WRAP
    };
    let home_ref = &home;
    let created = std::thread::scope(|scope| {
        let pause = crate::agents::arm_agent_writer_pause(home_ref.temp.path(), point);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if import_pauses {
            let tx = done_tx;
            let same_kit = same.clone();
            let same_import = scope.spawn(move || {
                let result = drive(import_kit(home_ref, same_kit, false));
                let _ = tx.send(format!("{result:?}"));
                result
            });
            wait_for_the_pause(home_ref.temp.path(), &done_rx);
            let different_kit = different.clone();
            let different_import =
                scope.spawn(move || drive(import_kit(home_ref, different_kit, false)));
            let create = scope.spawn(move || create_racing_agent(home_ref, "two-import-create"));
            both_stay_through_one_window(
                &different_import,
                &create,
                "the other import did not wait for the writer",
                "create did not wait for the writer",
            );
            drop(pause);
            let same_result = same_import.join().unwrap();
            let _different_result = different_import.join().unwrap();
            let created = create.join().unwrap();
            same_result.expect("the import that holds the key in force is stored");
            created
        } else {
            let tx = done_tx;
            let create = scope.spawn(move || {
                let result = create_racing_agent(home_ref, "two-import-create-first");
                let _ = tx.send(format!("{result:?}"));
                result
            });
            wait_for_the_pause(home_ref.temp.path(), &done_rx);
            let same_import = scope.spawn(move || drive(import_kit(home_ref, same, false)));
            let different_import =
                scope.spawn(move || drive(import_kit(home_ref, different, false)));
            both_stay_through_one_window(
                &same_import,
                &different_import,
                "the same-key import decided before the writer and did not hold it",
                "the other import did not wait for the writer",
            );
            drop(pause);
            let created = create.join().unwrap();
            let same_result = same_import.join().unwrap();
            let different_result = different_import.join().unwrap();
            same_result.expect("the import that holds the key in force is stored");
            assert_eq!(
                different_result
                    .expect_err("the other kit is refused once the agent exists")
                    .to_string(),
                crate::agents::agents_would_stop_opening(1)
            );
            assert_eq!(stored_key_id(home_ref), old_key);
            created
        }
    });
    let created = created.expect("create");
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
    let owner = crate::auth::stored_principal_record(home.temp.path(), &home.principal_id)
        .unwrap()
        .unwrap();
    let caller = crate::agents::Caller {
        principal_id: &home.principal_id,
        proof_binding_id: &owner.proof_binding_id,
        session_id: "session:after-refusal",
    };
    let listed = crate::agents::list(home.temp.path(), &caller)
        .expect("the agent file loads after the refused reassignment");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].agent_id, planted.agent_id);
    assert!(listed[0].retired_at.is_some());
}

#[tokio::test]
async fn reassignment_allows_when_this_owner_has_no_agents() {
    let home = imported_home();
    assert!(crate::agents::agent_file_path(home.temp.path())
        .unwrap()
        .symlink_metadata()
        .is_err());
    let other = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Guest,
        "gateway-test-no-agents-reassign",
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
    assert_ne!(kit.principal_id, home.principal_id);
    assert_eq!(kit.principal_id, other_principal.principal_id);
    let response = import_kit(&home, kit, true)
        .await
        .expect("an owner with no agents can be reassigned");
    assert_eq!(response.status, "reassigned");
    assert_eq!(response.principal_id, other.principal_id);
}

/// A protection whose archive is missing is a named refusal. The import
/// does not answer 500, and it does not store a new key over the agent.
#[tokio::test]
async fn a_missing_archive_does_not_turn_the_import_into_a_server_error() {
    let home = imported_home();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &home.principal_id,
        "plant-missing-archive",
    );
    let kit = different_root_key(&home);
    let mut stored = crate::auth::load_principal_root_protection(
        home.temp.path(),
        &home.principal_id,
        &home.localhost_root,
    )
    .unwrap()
    .unwrap();
    let key_before = stored.data_key_id.clone();
    let note = std::fs::read(&planted.path).unwrap();
    stored.protectors[0].archive = None;
    crate::auth::store_principal_root_protection(home.temp.path(), stored).unwrap();
    let agent_file = agent_bytes(home.temp.path());
    let err = import_kit(&home, kit, false)
        .await
        .expect_err("a missing archive refuses the import");
    assert!(err.is::<crate::agents::Refused>());
    assert_eq!(err.to_string(), crate::agents::CANNOT_OPEN_THE_WRAP);
    let response = crate::api::auth_gateway::auth_error_response(err);
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(stored_key_id(&home), key_before);
    assert_eq!(agent_bytes(home.temp.path()), agent_file);
    assert_eq!(std::fs::read(&planted.path).unwrap(), note);
}

fn archive_key_path(dir: &std::path::Path) -> std::path::PathBuf {
    elastos_common::localhost::rooted_localhost_fs_path(dir, "ElastOS/System/Auth")
        .unwrap()
        .join("recovery-archive.key")
}

fn home_whose_agent_opens(
    label: &str,
) -> (
    ImportedHome,
    crate::agents::tests::PlantedAgent,
    elastos_runtime::auth::RecoveryKitV1,
) {
    let home = imported_home();
    let planted =
        crate::agents::tests::plant_opening_agent(home.temp.path(), &home.principal_id, label);
    let kit = different_root_key(&home);
    (home, planted, kit)
}

async fn refused_without_touching_the_key_file(
    home: &ImportedHome,
    planted: &crate::agents::tests::PlantedAgent,
    kit: elastos_runtime::auth::RecoveryKitV1,
    key_before: &[u8],
) {
    let key_id = stored_key_id(home);
    let agents = agent_bytes(home.temp.path());
    let note_file = std::fs::read(&planted.path).unwrap();
    let err = import_kit(home, kit, false)
        .await
        .expect_err("the owner's key did not open");
    assert_eq!(err.to_string(), crate::agents::CANNOT_OPEN_THE_WRAP);
    assert_eq!(stored_key_id(home), key_id);
    assert_eq!(agent_bytes(home.temp.path()), agents);
    assert_eq!(std::fs::read(&planted.path).unwrap(), note_file);
    let path = archive_key_path(home.temp.path());
    if key_before.is_empty() {
        assert!(
            !path.exists(),
            "a missing recovery archive key stays missing"
        );
    } else {
        assert_eq!(std::fs::read(&path).unwrap(), key_before);
    }
}

/// The owner's archive key, tried by itself. Missing, damaged, and wrong are
/// not "this agent is closed", and the decision creates no key file.
#[tokio::test]
async fn the_owners_archive_key_is_not_read_as_an_agent_already_closed() {
    let (home, planted, kit) = home_whose_agent_opens("plant-key-missing");
    let path = archive_key_path(home.temp.path());
    assert!(path.is_file());
    std::fs::remove_file(&path).unwrap();
    refused_without_touching_the_key_file(&home, &planted, kit, b"").await;

    let (home, planted, kit) = home_whose_agent_opens("plant-key-damaged");
    let path = archive_key_path(home.temp.path());
    let damaged = b"short".to_vec();
    std::fs::write(&path, &damaged).unwrap();
    refused_without_touching_the_key_file(&home, &planted, kit, &damaged).await;

    let (home, planted, kit) = home_whose_agent_opens("plant-key-wrong");
    let path = archive_key_path(home.temp.path());
    let wrong = vec![7u8; 32];
    std::fs::write(&path, &wrong).unwrap();
    refused_without_touching_the_key_file(&home, &planted, kit, &wrong).await;
}

/// The owner's key opens. The agent's wrap was made under another key, so the
/// agent counts as closed and the import is not the cannot-open refusal.
#[tokio::test]
async fn an_agent_wrapped_under_another_key_counts_as_closed() {
    let (home, planted, kit) = home_whose_agent_opens("plant-other-wrap");
    let path = crate::agents::agent_file_path(home.temp.path()).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let slot =
        &mut value["agents"][0]["protection"]["protectors"][0]["envelope"]["wrapped_data_key"];
    let mut text = slot.as_str().unwrap().to_string().into_bytes();
    text[0] = if text[0] == b'A' { b'B' } else { b'A' };
    *slot = serde_json::Value::String(String::from_utf8(text).unwrap());
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        crate::agents::opening_agent_count(home.temp.path(), &home.principal_id).unwrap(),
        0,
        "the wrap does not open, and the owner's key did"
    );
    let new_key = kit.data_key_id.clone();
    let response = import_kit(&home, kit, false)
        .await
        .expect("an agent already closed does not refuse the import");
    assert_eq!(response.status, "imported");
    assert_eq!(stored_key_id(&home), new_key);
    let file: serde_json::Value = serde_json::from_slice(&agent_bytes(home.temp.path())).unwrap();
    assert_eq!(
        file["agents"][0]["record"]["principal_id"],
        planted.agent_id
    );
}

/// Two reassignments of one passkey. The first pauses under the writer. The
/// second is waiting. When the first rebinds the passkey, the second looks
/// the passkey up again and refuses by name.
#[tokio::test]
async fn two_reassignments_paused_at_the_seam_refuse_when_the_passkey_moves() {
    let home = imported_home();
    let binding = crate::auth::stored_principal_record(home.temp.path(), &home.principal_id)
        .unwrap()
        .unwrap()
        .proof_binding_id;
    let second = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Admin,
        "race-reassign-p2",
    );
    let second_protection =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &second.principal_id);
    let second_kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        second_protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    let planted = crate::agents::tests::plant_opening_agent(
        home.temp.path(),
        &second.principal_id,
        "plant-race-reassign",
    );
    let third = passkey_authority_with_name_role_credential(
        home.temp.path(),
        None,
        crate::auth::RuntimePrincipalRole::Guest,
        "race-reassign-p3",
    );
    let third_protection =
        crate::auth::store_test_principal_root_protection(home.temp.path(), &third.principal_id);
    let third_kit = crate::auth::recovery_kit_from_archive(
        home.temp.path(),
        third_protection.protectors[0].archive.as_ref().unwrap(),
    )
    .unwrap();
    let home_ref = &home;
    let (first, second_result) = std::thread::scope(|scope| {
        let pause = crate::agents::arm_agent_writer_pause(
            home_ref.temp.path(),
            crate::agents::PAUSE_BEFORE_STORE,
        );
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let tx = done_tx.clone();
        let first = scope.spawn(move || {
            let result = drive(import_kit(home_ref, second_kit, true));
            let _ = tx.send(format!("{result:?}"));
            result
        });
        wait_for_the_pause(home_ref.temp.path(), &done_rx);
        let second_import = scope.spawn(move || drive(import_kit(home_ref, third_kit, true)));
        assert!(
            still_running(&second_import),
            "the second reassignment did not wait for the writer"
        );
        drop(pause);
        let first = first.join().unwrap();
        let second_result = second_import.join().unwrap();
        (first, second_result)
    });
    let response = first.expect("the first reassignment binds the passkey to the agent owner");
    assert_eq!(response.status, "reassigned");
    assert_eq!(response.principal_id, second.principal_id);
    assert_eq!(
        second_result
            .expect_err("the passkey no longer names the account the request started with")
            .to_string(),
        crate::agents::PASSKEY_NO_LONGER_NAMES
    );
    let bound = crate::auth::load_principal_for_proof_binding(home.temp.path(), &binding).unwrap();
    assert_eq!(bound.principal_id, second.principal_id);
    assert_ne!(bound.principal_id, third.principal_id);
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
        "the agent's note still opens for the owner the first reassignment kept"
    );
}

/// Create Recovery Kit, through the export route. A protection with no archive
/// and an agent of this owner is refused with the kit sentence, and the key
/// stays. The step-up is still unused.
#[tokio::test]
async fn create_recovery_kit_refuses_when_an_unarchived_key_would_seal_an_agent() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(wallet_test_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    crate::auth::store_test_principal_root_protection(dir.path(), &owner.principal_id);
    let principal =
        crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id).unwrap();
    let planted = crate::agents::tests::plant_opening_agent(
        dir.path(),
        &owner.principal_id,
        "plant-create-kit",
    );
    let mut stored = crate::auth::load_principal_root_protection(
        dir.path(),
        &owner.principal_id,
        &principal.localhost_root,
    )
    .unwrap()
    .unwrap();
    let key_before = stored.data_key_id.clone();
    stored.protectors[0].archive = None;
    crate::auth::store_principal_root_protection(dir.path(), stored).unwrap();
    let agents = agent_bytes(dir.path());
    let note_file = std::fs::read(&planted.path).unwrap();
    let intent = json!({
        "principal_id": owner.principal_id,
        "localhost_root": principal.localhost_root,
        "label": "Kit",
        "download_password": null,
    });
    let token = step_up_token_for_app_context(
        dir.path(),
        SYSTEM_CAPSULE_ID,
        &owner.system_token,
        "auth.full-recovery-bundle.export",
        &intent,
    );
    let mut request = intent.clone();
    request["schema"] = json!("elastos.full-recovery-bundle.export.request/v1");
    request["step_up_token"] = json!(token);
    let response = app
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri("/api/auth/recovery/full-export")
                .header("x-elastos-home-token", owner.system_token.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        crate::agents::agents_use_a_key_not_in_a_kit(1)
    );
    assert!(
        !super::step_up_was_spent(dir.path()),
        "hold_unarchived's refusal leaves the step-up unspent"
    );
    let after = crate::auth::load_principal_root_protection(
        dir.path(),
        &owner.principal_id,
        &principal.localhost_root,
    )
    .unwrap()
    .unwrap();
    assert_eq!(after.data_key_id, key_before);
    assert!(after.protectors[0].archive.is_none());
    assert_eq!(agent_bytes(dir.path()), agents);
    assert_eq!(std::fs::read(&planted.path).unwrap(), note_file);
}

/// Create Recovery Kit through full-export, with the archive removed so
/// `hold_unarchived` runs. `prepare` may write the agents file first.
async fn export_unarchived(
    prepare: impl FnOnce(&std::path::Path, &str),
) -> (StatusCode, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(wallet_test_state(dir.path()).await);
    let owner = passkey_authority(dir.path());
    crate::auth::store_test_principal_root_protection(dir.path(), &owner.principal_id);
    let principal =
        crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id).unwrap();
    prepare(dir.path(), &owner.principal_id);
    let mut stored = crate::auth::load_principal_root_protection(
        dir.path(),
        &owner.principal_id,
        &principal.localhost_root,
    )
    .unwrap()
    .unwrap();
    stored.protectors[0].archive = None;
    crate::auth::store_principal_root_protection(dir.path(), stored).unwrap();
    let intent = json!({
        "principal_id": owner.principal_id,
        "localhost_root": principal.localhost_root,
        "label": "Kit",
        "download_password": null,
    });
    let token = step_up_token_for_app_context(
        dir.path(),
        SYSTEM_CAPSULE_ID,
        &owner.system_token,
        "auth.full-recovery-bundle.export",
        &intent,
    );
    let mut request = intent;
    request["schema"] = json!("elastos.full-recovery-bundle.export.request/v1");
    request["step_up_token"] = json!(token);
    let response = app
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri("/api/auth/recovery/full-export")
                .header("x-elastos-home-token", owner.system_token.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), dir)
}

fn mode_0600(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn full_export_with_no_agents_file_still_saves_the_kit() {
    let (status, body, dir) = export_unarchived(|_, _| {}).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("elastos.full-recovery-bundle/v1"), "{body}");
    assert!(!crate::agents::agent_file_path(dir.path()).unwrap().exists());
    assert!(super::step_up_was_spent(dir.path()));
}

#[tokio::test]
async fn full_export_with_only_a_retired_agent_still_saves_the_kit() {
    let (status, body, dir) = export_unarchived(|path, owner| {
        let planted = crate::agents::tests::plant_opening_agent(path, owner, "export-retired-only");
        let record = crate::auth::stored_principal_record(path, owner)
            .unwrap()
            .unwrap();
        let caller = crate::agents::Caller {
            principal_id: owner,
            proof_binding_id: &record.proof_binding_id,
            session_id: "session:export-retired",
        };
        crate::agents::retire(path, &caller, &planted.agent_id, 11).unwrap();
    })
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("elastos.full-recovery-bundle/v1"), "{body}");
    let saved = String::from_utf8(agent_bytes(dir.path())).unwrap();
    assert!(saved.contains("\"retired_at\": 11") || saved.contains("\"retired_at\":11"));
    assert!(super::step_up_was_spent(dir.path()));
}

#[tokio::test]
async fn full_export_of_a_damaged_agents_file_names_the_refusal_and_leaves_the_step_up() {
    let (status, body, dir) = export_unarchived(|path, _| {
        mode_0600(&crate::agents::agent_file_path(path).unwrap(), b"{");
    })
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, "agents are unavailable: agent file does not parse");
    assert!(
        !super::step_up_was_spent(dir.path()),
        "hold_unarchived's refusal leaves the step-up unspent"
    );
    assert_eq!(
        std::fs::read(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap(),
        b"{"
    );
}

/// Add a replacement passkey, revoke the first, and the owner still lists
/// and opens every agent with the same id and the same data.
#[tokio::test]
async fn a_replacement_passkey_lists_and_opens_every_agent() {
    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let now = crate::auth::now_ts();
    let credential_id = "owner-passkey-u5";
    let mut store = elastos_identity::IdentityStore::new(dir.path()).unwrap();
    store.load().unwrap();
    store.add_credential(elastos_identity::StoredCredential {
        credential_id: credential_id.to_string(),
        public_key: format!("{credential_id}-public-key"),
        sign_count: 1,
        rp_id: "localhost".to_string(),
    });
    store.save().unwrap();
    let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
        credential_id: credential_id.to_string(),
        public_key: format!("{credential_id}-public-key"),
        sign_count: 1,
        user_verified: true,
        origin: "http://localhost:61180".to_string(),
        rp_id: "localhost".to_string(),
        created_at: now,
        last_used_at: now,
        revoked_at: None,
    });
    let principal_id =
        crate::auth::passkey_credential_principal_id("localhost", credential_id).unwrap();
    let owner = crate::auth::upsert_principal_for_binding_as_role_named(
        dir.path(),
        binding,
        principal_id,
        crate::auth::RuntimePrincipalRole::Admin,
        Some("Account holder"),
        now,
    )
    .unwrap();
    let first_binding = owner.proof_binding_id.clone();
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", uuid_like_token()),
        session_id: format!("auth:{}", uuid_like_token()),
        principal_id: owner.principal_id.clone(),
        proof_binding_id: first_binding.clone(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        apps: vec![HOME_CAPSULE_ID.to_string(), SYSTEM_CAPSULE_ID.to_string()],
    };
    crate::auth::store_session_grant(dir.path(), grant.clone()).unwrap();
    let home_token =
        issue_home_launch_token_for_auth_grant(dir.path(), HOME_CAPSULE_ID, &grant).unwrap();
    let system_token = issue_home_projection_launch_token_with_context(
        dir.path(),
        SYSTEM_CAPSULE_ID,
        SYSTEM_CAPSULE_ID,
        &HomeLaunchTokenContext::for_test(
            grant.principal_id.clone(),
            grant.session_id.clone(),
            Some(grant.proof_binding_id.clone()),
            grant.grant_id.clone(),
            crate::auth::PrincipalKind::Human,
        ),
    )
    .unwrap();
    crate::auth::store_test_principal_root_protection(dir.path(), &owner.principal_id);
    let first = crate::agents::tests::plant_opening_agent(
        dir.path(),
        &owner.principal_id,
        "plant-passkey-a",
    );
    let second = crate::agents::tests::plant_opening_agent(
        dir.path(),
        &owner.principal_id,
        "plant-passkey-b",
    );
    let agent_file = std::fs::read(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap();
    let app = gateway_router(test_state(dir.path()));
    let step_up = issue_passkey_step_up_token_for_test(
        dir.path(),
        &system_token,
        SYSTEM_CAPSULE_ID,
        "auth.passkey.add",
        &json!({ "schema": "elastos.auth.passkey.add.intent/v1" }),
    )
    .unwrap();
    let (status, begin) = post_json(
        &app,
        "/api/auth/passkey/add/begin",
        &home_token,
        json!({
            "schema": "elastos.auth.passkey.add.begin.request/v1",
            "app_token": system_token,
            "step_up_token": step_up,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    let challenge = begin["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("begin returns a challenge");
    let attestation = crate::auth::passkey_attestation_with_id_for_test(
        challenge,
        "localhost",
        "http://localhost:61180",
        b"replacement-passkey-u5",
    );
    let (status, added) = post_json(
        &app,
        "/api/auth/passkey/add/complete",
        &home_token,
        json!({
            "schema": "elastos.auth.passkey.add.complete.request/v1",
            "app_token": system_token,
            "ceremony_id": begin["ceremony_id"],
            "response": attestation,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{added}");
    let replacement_binding = added["proof_binding_id"]
        .as_str()
        .expect("the added passkey names its binding")
        .to_string();
    assert_ne!(replacement_binding, first_binding);
    let replacement =
        crate::auth::load_principal_for_proof_binding(dir.path(), &replacement_binding).unwrap();
    assert_eq!(replacement.principal_id, owner.principal_id);
    let now = crate::auth::now_ts();
    let next = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", uuid_like_token()),
        session_id: format!("auth:{}", uuid_like_token()),
        principal_id: replacement.principal_id.clone(),
        proof_binding_id: replacement_binding.clone(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        apps: vec![HOME_CAPSULE_ID.to_string(), SYSTEM_CAPSULE_ID.to_string()],
    };
    crate::auth::store_session_grant(dir.path(), next.clone()).unwrap();
    let next_home =
        issue_home_launch_token_for_auth_grant(dir.path(), HOME_CAPSULE_ID, &next).unwrap();
    let next_system =
        issue_home_launch_token_for_auth_grant(dir.path(), SYSTEM_CAPSULE_ID, &next).unwrap();
    let (status, revoked) = post_json(
        &app,
        &format!("/api/auth/passkeys/{first_binding}/revoke"),
        &next_home,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["status"], "revoked");
    let first_record =
        crate::auth::load_principal_for_proof_binding(dir.path(), &first_binding).unwrap();
    assert!(first_record
        .proof_binding
        .passkey
        .unwrap()
        .revoked_at
        .is_some());
    let listed = app
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("GET")
                .uri("/api/apps/system/agents")
                .header("x-elastos-home-token", next_system)
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
    let mut ids: Vec<&str> = listed["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|agent| agent["agent_id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    let mut expected = vec![first.agent_id.as_str(), second.agent_id.as_str()];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    assert_eq!(
        std::fs::read(crate::agents::agent_file_path(dir.path()).unwrap()).unwrap(),
        agent_file,
        "the agent file is unchanged"
    );
    for planted in [&first, &second] {
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
}

async fn post_json(app: &Router, path: &str, home_token: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "http://localhost:61180")
                .method("POST")
                .uri(path)
                .header("x-elastos-home-token", home_token)
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
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    (status, value)
}
