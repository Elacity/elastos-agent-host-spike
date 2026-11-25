//! The owner's agent routes, driven through the gateway router.
//!
//! `off` runs in a build without the feature and `on` in a build with it.

#![cfg(unix)]

use super::*;

const ENABLE: &str = "/api/apps/system/agents/enable";
const DISABLE: &str = "/api/apps/system/agents/disable";
const CREATE: &str = "/api/apps/system/agents/create";
const RETIRE: &str = "/api/apps/system/agents/retire";
const RENAME: &str = "/api/apps/system/agents/rename";
const ACTIVATE: &str = "/api/apps/system/agents/activate";
#[cfg(not(feature = "prototype-agents"))]
const LAUNCH: &str = "/api/apps/system/agents/launch";
#[cfg(not(feature = "prototype-agents"))]
const STOP: &str = "/api/apps/system/agents/stop";
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

    #[cfg(unix)]
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
            (RETIRE, Some(json!({ "agent_id": &agent_id }))),
            (
                RENAME,
                Some(json!({ "agent_id": &agent_id, "display_name": "Helper 2" })),
            ),
            (
                ACTIVATE,
                Some(json!({ "agent_id": &agent_id, "active": true })),
            ),
            (
                LAUNCH,
                Some(json!({ "agent_id": &agent_id, "step_up_token": "step-up" })),
            ),
            (STOP, Some(json!({ "agent_id": &agent_id }))),
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

    struct OwnerHome {
        dir: tempfile::TempDir,
        state: crate::api::gateway::GatewayState,
        home_token: String,
        proof_binding_id: String,
        principal_id: String,
        localhost_root: String,
    }

    fn owner_home() -> OwnerHome {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let owner = protected_owner(dir.path());
        let principal =
            crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id)
                .unwrap();
        OwnerHome {
            dir,
            state,
            home_token: owner.home_token,
            proof_binding_id: owner.proof_binding_id,
            principal_id: principal.principal_id,
            localhost_root: principal.localhost_root,
        }
    }

    fn different_key(home: &OwnerHome) -> elastos_runtime::auth::RecoveryKitV1 {
        let current = crate::auth::load_principal_root_protection(
            home.dir.path(),
            &home.principal_id,
            &home.localhost_root,
        )
        .unwrap()
        .unwrap();
        let replacement =
            crate::auth::store_test_principal_root_protection(home.dir.path(), &home.principal_id);
        let kit = crate::auth::recovery_kit_from_archive(
            home.dir.path(),
            replacement.protectors[0].archive.as_ref().unwrap(),
        )
        .unwrap();
        assert_ne!(kit.data_key_id, current.data_key_id);
        crate::auth::store_principal_root_protection(home.dir.path(), current).unwrap();
        kit
    }

    async fn import_kit(
        home: &OwnerHome,
        kit: elastos_runtime::auth::RecoveryKitV1,
        reassign: bool,
    ) -> anyhow::Result<crate::api::auth_gateway::RecoveryKitImportResponse> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-elastos-home-token", home.home_token.parse().unwrap());
        headers.insert("host", "localhost:61180".parse().unwrap());
        headers.insert("origin", "http://localhost:61180".parse().unwrap());
        crate::api::auth_gateway::recovery_kit_import_inner(
            &home.state,
            &headers,
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

    fn auth_bytes(dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(crate::auth::auth_state_path(dir).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn root_key_change_refuses_when_the_file_holds_an_opening_agent() {
        let home = owner_home();
        crate::agents::tests::plant_enabled_home_with_one_agent(
            home.dir.path(),
            &home.principal_id,
            &home.proof_binding_id,
        );
        let kit = different_key(&home);
        let auth = auth_bytes(home.dir.path());
        let agents = std::fs::read(agent_file(home.dir.path())).unwrap();
        let err = import_kit(&home, kit, false)
            .await
            .expect_err("a root-key change must be refused while an agent's data opens")
            .to_string();
        assert_eq!(err, crate::agents::agents_would_stop_opening(1));
        assert_eq!(auth_bytes(home.dir.path()), auth);
        assert_eq!(std::fs::read(agent_file(home.dir.path())).unwrap(), agents);
    }

    #[tokio::test]
    async fn root_key_change_with_no_agents_file_stores_the_kit() {
        let home = owner_home();
        let kit = different_key(&home);
        let new_key = kit.data_key_id.clone();
        assert!(
            std::fs::symlink_metadata(agent_file(home.dir.path()))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "this owner has no agents file"
        );
        let before = data_root_entries(home.dir.path());
        let response = import_kit(&home, kit, false)
            .await
            .expect("an owner with no agents file imports as before");
        assert_eq!(response.status, "imported");
        assert_person_without_agents_leaves_no_agent_file(
            &before,
            &data_root_entries(home.dir.path()),
        );
        let stored = crate::auth::load_principal_root_protection(
            home.dir.path(),
            &home.principal_id,
            &home.localhost_root,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.data_key_id, new_key);
        assert!(
            std::fs::symlink_metadata(agent_file(home.dir.path()))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "the import does not create an agents file"
        );
    }

    #[tokio::test]
    async fn root_key_change_names_an_agents_file_this_build_cannot_read() {
        let home = owner_home();
        std::fs::write(agent_file(home.dir.path()), b"not an agent file").unwrap();
        let kit = different_key(&home);
        let auth = auth_bytes(home.dir.path());
        let err = import_kit(&home, kit, false)
            .await
            .expect_err("an unreadable agents file refuses the root-key change")
            .to_string();
        assert_eq!(err, crate::agents::AGENTS_FILE_UNREADABLE);
        assert_eq!(auth_bytes(home.dir.path()), auth);
        assert_eq!(
            std::fs::read(agent_file(home.dir.path())).unwrap(),
            b"not an agent file"
        );
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
                .all(|entry| { entry == "ElastOS/System/Auth/principal-root-lifecycle.lock" }),
            "the whole data root gained {added:?}"
        );
        assert!(
            after.iter().all(|entry| {
                !entry.ends_with("agent-records.json")
                    && !entry.ends_with("agent-records.json.lock")
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

    fn write_0600(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the fixture is mode 0600"
        );
    }

    /// A fixed agent file at mode 0600. The default build reads it as plain
    /// JSON and does not open a key.
    #[tokio::test]
    async fn root_key_change_reads_a_0600_fixture_without_a_key() {
        let home = owner_home();
        let naming_owner = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [{ "record": { "owner": home.principal_id } }]
        }))
        .unwrap();
        write_0600(&agent_file(home.dir.path()), &naming_owner);
        let kit = different_key(&home);
        let auth = auth_bytes(home.dir.path());
        let err = import_kit(&home, kit, false)
            .await
            .expect_err("a record that names this owner refuses the root-key change")
            .to_string();
        assert_eq!(err, crate::agents::agents_would_stop_opening(1));
        assert_eq!(auth_bytes(home.dir.path()), auth);
        assert_eq!(
            std::fs::read(agent_file(home.dir.path())).unwrap(),
            naming_owner
        );

        let home = owner_home();
        let other_owners = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [{ "record": { "owner": "person:local:someone-else" } }]
        }))
        .unwrap();
        write_0600(&agent_file(home.dir.path()), &other_owners);
        let kit = different_key(&home);
        let new_key = kit.data_key_id.clone();
        let response = import_kit(&home, kit, false)
            .await
            .expect("a file that names only other owners leaves this owner free");
        assert_eq!(response.status, "imported");
        let stored = crate::auth::load_principal_root_protection(
            home.dir.path(),
            &home.principal_id,
            &home.localhost_root,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.data_key_id, new_key);
        assert_eq!(
            std::fs::read(agent_file(home.dir.path())).unwrap(),
            other_owners
        );

        let home = owner_home();
        write_0600(&agent_file(home.dir.path()), b"not json");
        let kit = different_key(&home);
        let auth = auth_bytes(home.dir.path());
        let err = import_kit(&home, kit, false)
            .await
            .expect_err("an unreadable file refuses with its own reason")
            .to_string();
        assert_eq!(err, crate::agents::AGENTS_FILE_UNREADABLE);
        assert_eq!(auth_bytes(home.dir.path()), auth);

        let home = owner_home();
        let oversized = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [{ "record": { "owner": home.principal_id } }],
            "pad": " ".repeat(crate::agents::MAX_AGENT_FILE_BYTES as usize)
        }))
        .unwrap();
        assert!(oversized.len() as u64 > crate::agents::MAX_AGENT_FILE_BYTES);
        write_0600(&agent_file(home.dir.path()), &oversized);
        let kit = different_key(&home);
        let err = import_kit(&home, kit, false)
            .await
            .expect_err("a file past the read bound refuses as unreadable")
            .to_string();
        assert_eq!(err, crate::agents::AGENTS_FILE_UNREADABLE);
    }

    /// A retired record does not stop a root-key change. An unretired one
    /// does, and that refusal opens no key and creates no key file.
    #[tokio::test]
    async fn root_key_change_counts_unretired_records_and_creates_no_key_file() {
        let home = owner_home();
        let retired = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [{ "record": { "owner": home.principal_id, "retired_at": 4 } }]
        }))
        .unwrap();
        write_0600(&agent_file(home.dir.path()), &retired);
        let kit = different_key(&home);
        let response = import_kit(&home, kit, false)
            .await
            .expect("a retired record does not stop a root-key change");
        assert_eq!(response.status, "imported");
        assert_eq!(std::fs::read(agent_file(home.dir.path())).unwrap(), retired);

        let home = owner_home();
        let mixed = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [
                { "record": { "owner": home.principal_id, "retired_at": 4 } },
                { "record": { "owner": home.principal_id, "retired_at": null } }
            ]
        }))
        .unwrap();
        write_0600(&agent_file(home.dir.path()), &mixed);
        let kit = different_key(&home);
        let key_file = home
            .dir
            .path()
            .join("ElastOS/System/Auth/recovery-archive.key");
        assert!(
            key_file.is_file(),
            "building the kit writes the archive key, so the import can be checked for creating one"
        );
        std::fs::remove_file(&key_file).unwrap();
        let err = import_kit(&home, kit, false)
            .await
            .expect_err(
                "one unretired record refuses, and the retired one does not add to the count",
            )
            .to_string();
        assert_eq!(err, crate::agents::agents_would_stop_opening(1));
        assert!(
            !key_file.exists(),
            "the decision opens no key and creates no key file"
        );
        assert_eq!(std::fs::read(agent_file(home.dir.path())).unwrap(), mixed);
    }

    /// The kit import route, with reassignment asked for. A record that names
    /// this owner, retired or not, refuses: the recovery would leave that
    /// agent belonging to nobody.
    #[tokio::test]
    async fn reassignment_refuses_when_a_record_names_this_owner() {
        let home = owner_home();
        crate::agents::tests::plant_enabled_home_with_one_agent(
            home.dir.path(),
            &home.principal_id,
            &home.proof_binding_id,
        );
        let other = passkey_authority_with_name_role_credential(
            home.dir.path(),
            None,
            crate::auth::RuntimePrincipalRole::Guest,
            "feature-off-reassign",
        );
        let other_protection =
            crate::auth::store_test_principal_root_protection(home.dir.path(), &other.principal_id);
        let kit = crate::auth::recovery_kit_from_archive(
            home.dir.path(),
            other_protection.protectors[0].archive.as_ref().unwrap(),
        )
        .unwrap();
        assert_ne!(kit.principal_id, home.principal_id);
        let auth = auth_bytes(home.dir.path());
        let agents = std::fs::read(agent_file(home.dir.path())).unwrap();
        let err = import_kit(&home, kit, true)
            .await
            .expect_err("a reassignment that changes the owner id a record names")
            .to_string();
        assert_eq!(err, crate::agents::agents_would_belong_to_nobody(1));
        assert_eq!(auth_bytes(home.dir.path()), auth);
        assert_eq!(std::fs::read(agent_file(home.dir.path())).unwrap(), agents);
    }

    /// A retired record alone still names this owner. Changing `false` to
    /// `true` in the plain count would let this reassignment through.
    #[tokio::test]
    async fn reassignment_refuses_when_only_a_retired_record_names_this_owner() {
        let home = owner_home();
        let retired = serde_json::to_vec(&json!({
            "schema": crate::agents::AGENT_RECORDS_SCHEMA,
            "agents": [{ "record": { "owner": home.principal_id, "retired_at": 4 } }]
        }))
        .unwrap();
        write_0600(&agent_file(home.dir.path()), &retired);
        let other = passkey_authority_with_name_role_credential(
            home.dir.path(),
            None,
            crate::auth::RuntimePrincipalRole::Guest,
            "feature-off-retired-reassign",
        );
        let other_protection =
            crate::auth::store_test_principal_root_protection(home.dir.path(), &other.principal_id);
        let kit = crate::auth::recovery_kit_from_archive(
            home.dir.path(),
            other_protection.protectors[0].archive.as_ref().unwrap(),
        )
        .unwrap();
        let auth = auth_bytes(home.dir.path());
        let err = import_kit(&home, kit, true)
            .await
            .expect_err("a retired record still names the owner this recovery changes")
            .to_string();
        assert_eq!(err, crate::agents::agents_would_belong_to_nobody(1));
        assert_eq!(auth_bytes(home.dir.path()), auth);
        assert_eq!(std::fs::read(agent_file(home.dir.path())).unwrap(), retired);
    }

    /// Create Recovery Kit through the export route. A protection with no
    /// archive, and an unretired record of this owner, is refused by the
    /// kit sentence. The step-up is still unused.
    #[tokio::test]
    async fn create_recovery_kit_refuses_when_an_unarchived_key_would_seal_an_agent() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(wallet_test_state(dir.path()).await);
        let owner = protected_owner(dir.path());
        let principal =
            crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id)
                .unwrap();
        crate::agents::tests::plant_enabled_home_with_one_agent(
            dir.path(),
            &owner.principal_id,
            &owner.proof_binding_id,
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
        let agents = std::fs::read(agent_file(dir.path())).unwrap();
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
        let (status, body) = call(
            &app,
            "/api/auth/recovery/full-export",
            &owner.system_token,
            Some(request),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, crate::agents::agents_use_a_key_not_in_a_kit(1));
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
        assert_eq!(std::fs::read(agent_file(dir.path())).unwrap(), agents);
    }

    /// Create Recovery Kit through full-export, with the archive removed so
    /// `hold_unarchived` runs. `prepare` may write the agents file first.
    async fn export_unarchived(
        prepare: impl FnOnce(&std::path::Path, &str),
    ) -> (StatusCode, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(wallet_test_state(dir.path()).await);
        let owner = protected_owner(dir.path());
        let principal =
            crate::auth::load_principal_for_proof_binding(dir.path(), &owner.proof_binding_id)
                .unwrap();
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
        let (status, body) = call(
            &app,
            "/api/auth/recovery/full-export",
            &owner.system_token,
            Some(request),
        )
        .await;
        (status, body, dir)
    }

    #[tokio::test]
    async fn full_export_with_no_agents_file_still_saves_the_kit() {
        let (status, body, dir) = export_unarchived(|_, _| {}).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("elastos.full-recovery-bundle/v1"), "{body}");
        assert!(!agent_file(dir.path()).exists());
        assert!(super::step_up_was_spent(dir.path()));
    }

    #[tokio::test]
    async fn full_export_with_only_a_retired_record_still_saves_the_kit() {
        let (status, body, dir) = export_unarchived(|path, owner| {
            let retired = serde_json::to_vec(&json!({
                "schema": crate::agents::AGENT_RECORDS_SCHEMA,
                "agents": [{ "record": { "owner": owner, "retired_at": 4 } }]
            }))
            .unwrap();
            write_0600(&agent_file(path), &retired);
        })
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("elastos.full-recovery-bundle/v1"), "{body}");
        let saved = std::fs::read(agent_file(dir.path())).unwrap();
        assert!(String::from_utf8_lossy(&saved).contains("retired_at"));
        assert!(super::step_up_was_spent(dir.path()));
    }

    #[tokio::test]
    async fn full_export_of_a_damaged_agents_file_names_the_refusal_and_leaves_the_step_up() {
        let (status, body, dir) = export_unarchived(|path, _| {
            write_0600(&agent_file(path), b"{");
        })
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, crate::agents::AGENTS_FILE_UNREADABLE);
        assert!(
            !super::step_up_was_spent(dir.path()),
            "hold_unarchived's refusal leaves the step-up unspent"
        );
        assert_eq!(std::fs::read(agent_file(dir.path())).unwrap(), b"{");
    }
}

#[cfg(feature = "prototype-agents")]
mod on {
    use super::*;
    use crate::agent_admission::tests::{installed_agent_host, Signed, AGENT_HOST};

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

    /// U3 acceptance: Home asks, Runtime owns the authority check and id.
    #[cfg(unix)]
    #[tokio::test]
    async fn u3_owner_create_replaces_admission_mint() {
        let installed = installed_home();
        let data = &installed.home.data;
        let app = &installed.app;
        let owner = &installed.owner;
        assert_eq!(
            call(app, ENABLE, &owner.system_token, None).await.0,
            StatusCode::OK
        );
        let before = std::fs::read(agent_file(data)).unwrap();

        // Create accepts no owner field, regardless of which admin sends it.
        let other = passkey_authority_with_name_role_credential(
            data,
            Some("Other Admin"),
            crate::auth::RuntimePrincipalRole::Admin,
            "u3-other-admin-passkey",
        );
        crate::auth::store_test_principal_root_protection(data, &other.principal_id);
        let mut owner_spoof = create_body("u3-spoof");
        owner_spoof["owner"] = json!(&owner.principal_id);
        let (status, reason) = call(app, CREATE, &other.system_token, Some(owner_spoof)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(reason.starts_with("agent request is invalid: "), "{reason}");
        assert_eq!(std::fs::read(agent_file(data)).unwrap(), before);

        let guest = passkey_authority_with_name_role(
            data,
            Some("Guest"),
            crate::auth::RuntimePrincipalRole::Guest,
        );
        crate::auth::store_test_principal_root_protection(data, &guest.principal_id);
        assert_eq!(
            call(
                app,
                CREATE,
                &guest.system_token,
                Some(create_body("u3-guest"))
            )
            .await,
            admin_required()
        );
        assert_eq!(std::fs::read(agent_file(data)).unwrap(), before);

        // Identical names and Hosts do not choose identity. Runtime chooses it.
        let mut ids = Vec::new();
        for request_id in ["u3-first", "u3-second"] {
            let body = create_body(request_id);
            let (status, answer) = call(app, CREATE, &owner.system_token, Some(body.clone())).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            let created: Value = serde_json::from_str(&answer).unwrap();
            let id = created["agent_id"].as_str().unwrap().to_string();
            assert!(crate::auth::validate_agent_id(&id).is_ok());
            assert_eq!(created["display_name"], "Helper");
            assert_eq!(created["active"], false);
            assert_eq!(
                call(app, CREATE, &owner.system_token, Some(body)).await,
                (StatusCode::OK, answer),
                "a retry keeps the Runtime id"
            );
            ids.push(id);
        }
        assert_ne!(ids[0], ids[1], "the name and Host do not derive the id");
        let stored: Value =
            serde_json::from_slice(&std::fs::read(agent_file(data)).unwrap()).unwrap();
        let rows = stored["agents"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for (row, id) in rows.iter().zip(&ids) {
            assert_eq!(row["record"]["principal_id"], id.as_str());
            assert_eq!(row["record"]["owner"], owner.principal_id);
            assert_eq!(row["active"], false);
        }

        // The old admission-time mint cannot turn an unknown id into a record.
        let written = std::fs::read(agent_file(data)).unwrap();
        let unknown = "agent:v2:ffffffffffffffffffffffffffffffff";
        let host_dir = data.join("capsules").join(AGENT_HOST);
        let refused = crate::agent_admission::admit_launch(
            data,
            data,
            Some(&owner.principal_id),
            Some(unknown),
            crate::agent_admission::walk_launch(&host_dir).unwrap(),
        )
        .unwrap_err();
        assert_eq!(refused.to_string(), "the caller owns no agent with that id");
        assert_eq!(std::fs::read(agent_file(data)).unwrap(), written);
    }

    /// A stored Agent can hold a valid token, but cannot ask Runtime to create.
    #[cfg(unix)]
    #[tokio::test]
    async fn u3_agent_principal_cannot_call_create() {
        let installed = installed_home();
        let agent_id = create_agent(&installed, "u3-agent-caller-setup").await;
        let data = &installed.home.data;
        let root = crate::auth::principal_kind_localhost_root(
            &agent_id,
            crate::auth::PrincipalKind::Agent,
        );
        let binding = crate::agents::stored_agent_for_root(data, &agent_id, &root)
            .unwrap()
            .unwrap()
            .record
            .proof_binding_id;
        let now = now_ts();
        let grant = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: format!("grant:{}", uuid_like_token()),
            session_id: format!("auth:{}", uuid_like_token()),
            principal_id: agent_id.clone(),
            proof_binding_id: binding.clone(),
            issued_at: now,
            expires_at: now + 3600,
            apps: vec![SYSTEM_CAPSULE_ID.to_string()],
        };
        crate::auth::store_session_grant(data, grant.clone()).unwrap();
        let agent_token =
            issue_home_launch_token_for_auth_grant(data, SYSTEM_CAPSULE_ID, &grant).unwrap();
        let before = std::fs::read(agent_file(data)).unwrap();
        assert_eq!(
            call(
                &installed.app,
                CREATE,
                &agent_token,
                Some(create_body("u3-agent-caller")),
            )
            .await,
            (
                StatusCode::FORBIDDEN,
                "Gateway request requires an admitted host and caller".to_string(),
            ),
        );
        assert_eq!(std::fs::read(agent_file(data)).unwrap(), before);

        let request = serde_json::from_value(create_body("u3-agent-store")).unwrap();
        let caller = crate::agents::Caller {
            principal_id: &agent_id,
            proof_binding_id: &binding,
            session_id: &grant.session_id,
        };
        assert_eq!(
            crate::agents::create(
                data,
                &caller,
                &request,
                |_| panic!("agent reached admit"),
                now
            )
            .unwrap_err()
            .to_string(),
            crate::agents::NOT_A_PERSON,
        );
        assert_eq!(std::fs::read(agent_file(data)).unwrap(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enable_needs_the_admin_passkey_owner() {
        let dir = tempfile::tempdir().unwrap();
        let app = gateway_router(test_state(dir.path()));
        // A stored guest, and a second guest's passkey.
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
            (
                RENAME,
                json!({
                    "agent_id": "agent:v2:0123456789abcdef0123456789abcdef",
                    "display_name": "Helper 2"
                }),
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

    #[cfg(unix)]
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
            (
                RENAME,
                Some(json!({
                    "agent_id": "agent:v2:0123456789abcdef0123456789abcdef",
                    "display_name": "Helper 2"
                })),
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

    #[cfg(unix)]
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
        let rename = json!({
            "agent_id": "agent:v2:0123456789abcdef0123456789abcdef",
            "display_name": "Helper 2"
        });
        assert_eq!(call(&app, RENAME, token, Some(rename)).await, off);
        assert!(!agent_file(dir.path()).exists());
    }

    #[cfg(unix)]
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
        assert_eq!(
            listed["agents"][0]["active"],
            json!(false),
            "the_list_returns_whether_each_agent_is_on"
        );

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

        let rename = json!({ "agent_id": &agent_id, "display_name": "Helper 2" });
        let (status, body) = call(&app, RENAME, token, Some(rename.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let renamed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(renamed["agent_id"], agent_id);
        assert_eq!(renamed["display_name"], "Helper 2");
        assert_eq!(renamed["retired_at"], Value::Null);
        let mut unknown = rename;
        unknown["owner"] = json!("person:local:someone");
        let (status, text) = call(&app, RENAME, token, Some(unknown)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(text.starts_with("agent request is invalid: "), "{text}");

        let retire = json!({ "agent_id": &agent_id });
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

    #[cfg(unix)]
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
        let renamed = agents_rename(
            state(),
            headers.clone(),
            body(json!({"agent_id": "a", "display_name": "Helper 2"})),
        );
        assert_eq!(answer(renamed.await).await, not_the_home);
        assert_eq!(std::fs::read(agent_file(&home.data)).unwrap(), written);
    }

    #[cfg(unix)]
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
        let rename = json!({
            "agent_id": "agent:v2:0123456789abcdef0123456789abcdef",
            "display_name": "Helper 2"
        });
        assert_eq!(call(&app, RENAME, token, Some(rename)).await, unavailable);
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

    async fn create_agent(installed: &InstalledHome, request_id: &str) -> String {
        let token = &installed.owner.system_token;
        assert_eq!(
            call(&installed.app, ENABLE, token, None).await.0,
            StatusCode::OK
        );
        let (status, body) =
            call(&installed.app, CREATE, token, Some(create_body(request_id))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str::<Value>(&body).unwrap()["agent_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_agent_off_until_owner_activation() {
        let installed = installed_home();
        let agent_id = create_agent(&installed, "off-1").await;
        let data = &installed.home.data;
        let owner = installed.owner.principal_id.as_str();
        let dir = data.join("capsules").join(AGENT_HOST);
        let launch = |id: &str| {
            crate::agent_admission::admit_launch(
                data,
                data,
                Some(owner),
                Some(id),
                crate::agent_admission::walk_launch(&dir).unwrap(),
            )
        };
        assert_eq!(
            launch(&agent_id).unwrap_err().to_string(),
            crate::agents::NOT_ACTIVE
        );
        let on = json!({ "agent_id": &agent_id, "active": true });
        assert_eq!(
            call(
                &installed.app,
                ACTIVATE,
                &installed.owner.system_token,
                Some(on)
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(launch(&agent_id).unwrap().unwrap().actor(), agent_id);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn another_admin_cannot_turn_on_someone_elses_agent() {
        let installed = installed_home();
        let agent_id = create_agent(&installed, "other-admin").await;
        let data = &installed.home.data;
        let other = passkey_authority_with_name_role_credential(
            data,
            Some("Other Admin"),
            crate::auth::RuntimePrincipalRole::Admin,
            "gateway-test-other-admin-passkey",
        );
        crate::auth::store_test_principal_root_protection(data, &other.principal_id);
        let stored =
            crate::auth::load_principal_for_proof_binding(data, &other.proof_binding_id).unwrap();
        assert!(crate::auth::is_admin(&stored));
        assert_ne!(stored.principal_id, installed.owner.principal_id);
        let owner = installed.owner.principal_id.as_str();
        let dir = data.join("capsules").join(AGENT_HOST);
        let launch = || {
            crate::agent_admission::admit_launch(
                data,
                data,
                Some(owner),
                Some(&agent_id),
                crate::agent_admission::walk_launch(&dir).unwrap(),
            )
        };
        let on = json!({ "agent_id": &agent_id, "active": true });
        let answer = call(&installed.app, ACTIVATE, &other.system_token, Some(on)).await;
        let launch_text = match launch() {
            Ok(_) => "launch admitted".to_string(),
            Err(error) => error.to_string(),
        };
        assert_eq!(
            (answer.0, answer.1, launch_text),
            (
                StatusCode::CONFLICT,
                "the caller owns no agent with that id".to_string(),
                crate::agents::NOT_ACTIVE.to_string(),
            ),
            "another_admin_cannot_turn_on_someone_elses_agent"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn owner_turns_agent_off_again() {
        let installed = installed_home();
        let agent_id = create_agent(&installed, "off-again").await;
        let data = &installed.home.data;
        let owner = installed.owner.principal_id.as_str();
        let dir = data.join("capsules").join(AGENT_HOST);
        let launch = |id: &str| {
            crate::agent_admission::admit_launch(
                data,
                data,
                Some(owner),
                Some(id),
                crate::agent_admission::walk_launch(&dir).unwrap(),
            )
        };
        let token = &installed.owner.system_token;
        assert_eq!(
            call(
                &installed.app,
                ACTIVATE,
                token,
                Some(json!({ "agent_id": &agent_id, "active": true }))
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(launch(&agent_id).unwrap().unwrap().actor(), agent_id);
        let (_, listed_on) = call(&installed.app, LIST, token, None).await;
        let listed_on: Value = serde_json::from_str(&listed_on).unwrap();
        assert_eq!(
            listed_on["agents"][0]["active"],
            json!(true),
            "the_list_returns_whether_each_agent_is_on"
        );
        let on_file: Value =
            serde_json::from_slice(&std::fs::read(agent_file(data)).unwrap()).unwrap();
        assert!(on_file["agents"][0].get("active").is_none());
        assert_eq!(
            call(
                &installed.app,
                ACTIVATE,
                token,
                Some(json!({ "agent_id": &agent_id, "active": false }))
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            launch(&agent_id).unwrap_err().to_string(),
            crate::agents::NOT_ACTIVE,
            "owner_turns_agent_off_again"
        );
        let off_file: Value =
            serde_json::from_slice(&std::fs::read(agent_file(data)).unwrap()).unwrap();
        assert_eq!(off_file["agents"][0]["active"], json!(false));
        let (_, listed_off) = call(&installed.app, LIST, token, None).await;
        let listed_off: Value = serde_json::from_str(&listed_off).unwrap();
        assert_eq!(
            listed_off["agents"][0]["active"],
            json!(false),
            "the_list_returns_whether_each_agent_is_on"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agent_cannot_activate_itself() {
        let installed = installed_home();
        let agent_id = create_agent(&installed, "self-1").await;
        let data = &installed.home.data;
        let root = crate::auth::principal_kind_localhost_root(
            &agent_id,
            crate::auth::PrincipalKind::Agent,
        );
        let binding = crate::agents::stored_agent_for_root(data, &agent_id, &root)
            .unwrap()
            .unwrap()
            .record
            .proof_binding_id;
        let now = now_ts();
        let grant = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: format!("grant:{}", uuid_like_token()),
            session_id: format!("auth:{}", uuid_like_token()),
            principal_id: agent_id.clone(),
            proof_binding_id: binding,
            issued_at: now,
            expires_at: now + 3600,
            apps: vec![SYSTEM_CAPSULE_ID.to_string()],
        };
        crate::auth::store_session_grant(data, grant.clone()).unwrap();
        let agent_token =
            issue_home_launch_token_for_auth_grant(data, SYSTEM_CAPSULE_ID, &grant).unwrap();
        // The front door refuses every agent principal before a route runs.
        // This calls the activate handler, so the refusal is the route's own
        // owner check. Dropping that check is what turns this assertion red.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("localhost:61180"),
        );
        headers.insert(
            axum::http::header::ORIGIN,
            axum::http::HeaderValue::from_static("null"),
        );
        headers.insert(
            "x-elastos-home-token",
            axum::http::HeaderValue::from_str(&agent_token).unwrap(),
        );
        let response = super::super::super::gateway_agents::agents_activate(
            axum::extract::State(installed.state.clone()),
            headers,
            axum::body::Bytes::from(json!({"agent_id": &agent_id, "active": true}).to_string()),
        )
        .await;
        assert_eq!(answer(response).await, admin_required());
        assert_eq!(
            crate::agents::stored_agent(data, &installed.owner.principal_id, &agent_id)
                .unwrap_err()
                .to_string(),
            crate::agents::NOT_ACTIVE
        );
    }
}
