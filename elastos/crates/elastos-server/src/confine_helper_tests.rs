//! Real localhost and object binaries, started through the confined path.
//!
//! The rustc probe is not this proof. Run
//! `localhost_and_object_providers_work_inside_their_fences` on Linux as well
//! as macOS. The test lives in the library so it can store a signed auth
//! record. `server_infra` is the binary crate and cannot see that helper.

use std::path::{Path, PathBuf};

/// Localhost and object do their file job and cannot open the device key.
///
/// macOS also refuses lstat. Linux Landlock does not mediate stat, so the
/// localhost stat of `identity/device.key` is `ok` and must not carry the key
/// bytes. The read stays an error. Removing the fence makes that read succeed.
/// Object init decides by open on Linux and by open plus lstat on macOS. A
/// successful init means that check passed. The parent then checks the key
/// bytes are unchanged.
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[tokio::test]
async fn localhost_and_object_providers_work_inside_their_fences() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    fn provider_binary(name: &str) -> PathBuf {
        let mut candidates = Vec::new();
        if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
            candidates.push(PathBuf::from(dir).join("debug").join(name));
        }
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        candidates.push(manifest.join("../../target/debug").join(name));
        // The test-elastos job builds object-provider into this directory.
        // localhost-provider is a workspace member and is not built there.
        candidates.push(
            manifest
                .join("../../../target/provider-fence-tests/debug")
                .join(name),
        );
        candidates.push(
            manifest
                .join("../../../capsules")
                .join(name)
                .join("target/debug")
                .join(name),
        );
        candidates
            .iter()
            .find(|path| path.is_file())
            .cloned()
            .unwrap_or_else(|| {
                panic!("build the {name} binary before this test; looked in {candidates:?}")
            })
    }

    fn pinned(path: &Path, data_dir: &Path) -> elastos_runtime::provider::CheckedExecutable {
        let digest = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
        elastos_runtime::provider::CheckedExecutable::pinned(path, &format!("sha256:{digest}"))
            .unwrap()
            .with_home_data_dir(data_dir)
    }

    fn data_root() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            let root = path.join(name);
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        (temp, path)
    }

    async fn exchange(
        bridge: &elastos_runtime::provider::ProviderBridge,
        request: serde_json::Value,
    ) -> serde_json::Value {
        bridge
            .send_raw(&request)
            .await
            .unwrap_or_else(|err| panic!("{request}: {err}"))
    }

    let secret = b"localhost-device-key-secret!!";
    let (_local_hold, data) = data_root();
    let identity = data.join("identity");
    std::fs::create_dir(&identity).unwrap();
    let key_path = identity.join("device.key");
    std::fs::write(&key_path, secret).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let binary = provider_binary("localhost-provider");
    let checked = pinned(&binary, &data);
    let confined = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "localhost-provider",
        &checked,
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            allowed_paths: vec!["*".to_string()],
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("localhost init failed: {err}"));
    let bridge = confined.bridge().clone();
    let wrote = exchange(
        &bridge,
        serde_json::json!({
            "op": "write",
            "path": "AppCapsules/note.txt",
            "content": b"hello-c2".to_vec(),
            "append": false
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    assert_eq!(
        std::fs::read(data.join("AppCapsules/note.txt")).unwrap(),
        b"hello-c2"
    );
    let read = exchange(
        &bridge,
        serde_json::json!({"op": "read", "path": "AppCapsules/note.txt", "encoding": "utf8"}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");
    assert_eq!(read["data"]["content"], "hello-c2");
    let deleted = exchange(
        &bridge,
        serde_json::json!({"op": "delete", "path": "AppCapsules/note.txt", "recursive": false}),
    )
    .await;
    assert_eq!(deleted["status"], "ok", "{deleted}");
    assert!(!data.join("AppCapsules/note.txt").exists());
    let made = exchange(
        &bridge,
        serde_json::json!({"op": "mkdir", "path": "AppCapsules/folder", "parents": false}),
    )
    .await;
    assert_eq!(made["status"], "ok", "{made}");
    let removed = exchange(
        &bridge,
        serde_json::json!({"op": "delete", "path": "AppCapsules/folder", "recursive": false}),
    )
    .await;
    assert_eq!(removed["status"], "ok", "{removed}");
    assert!(!data.join("AppCapsules/folder").exists());
    for op in ["stat", "read"] {
        let answer = exchange(
            &bridge,
            serde_json::json!({"op": op, "path": "identity/device.key"}),
        )
        .await;
        let text = answer.to_string();
        assert!(
            !text.contains("localhost-device-key-secret!!"),
            "{op}: {text}"
        );
        if op == "read" || !cfg!(target_os = "linux") {
            assert_eq!(answer["status"], "error", "{op}: {answer}");
        } else {
            // Landlock does not mediate stat. The read above is the fence:
            // if the fence is removed, open succeeds and this test fails.
            assert_eq!(
                answer["status"], "ok",
                "Linux stat of identity/device.key is not mediated by Landlock: {answer}"
            );
        }
    }
    assert_eq!(std::fs::read(&key_path).unwrap(), secret);
    bridge.shutdown().await.unwrap();

    let (_object_hold, object_data) = data_root();
    let principal = "person:local:ada";
    let record = crate::auth::store_test_human_principal(&object_data, principal);
    let (_, did) = elastos_identity::load_or_create_did(&object_data).unwrap();
    let runtime_did_file = object_data.join("ElastOS/System/Auth/runtime-did");
    assert!(
        !runtime_did_file.exists(),
        "the object helper has no runtime-did file"
    );
    let object_key = object_data.join("identity").join("device.key");
    let object_secret = std::fs::read(&object_key).unwrap();
    let object_secret_hex = hex::encode(&object_secret);
    let object_bin = provider_binary("object-provider");
    let object_checked = pinned(&object_bin, &object_data);
    let object = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "object-provider",
        &object_checked,
        &object_data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: object_data.display().to_string(),
            extra: serde_json::json!({ "runtime_did": did }),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("object init failed: {err}"));
    let object_bridge = object.bridge().clone();
    let uri = format!("{}/note.txt", record.localhost_root);
    let payload = base64::engine::general_purpose::STANDARD.encode(b"hello-object");
    let object_wrote = exchange(
        &object_bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": payload
        }),
    )
    .await;
    assert_eq!(object_wrote["status"], "ok", "{object_wrote}");
    let object_read = exchange(
        &object_bridge,
        serde_json::json!({"op": "read", "principal_id": principal, "uri": uri}),
    )
    .await;
    assert_eq!(object_read["status"], "ok", "{object_read}");
    assert_eq!(object_read["data"]["data"], payload);
    let folder = exchange(
        &object_bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": record.localhost_root,
            "name": "folder"
        }),
    )
    .await;
    assert_eq!(folder["status"], "ok", "{folder}");
    let folder_uri = format!("{}/folder", record.localhost_root);
    for target in [uri.as_str(), folder_uri.as_str()] {
        let trashed = exchange(
            &object_bridge,
            serde_json::json!({"op": "trash", "principal_id": principal, "uri": target}),
        )
        .await;
        assert_eq!(trashed["status"], "ok", "{target}: {trashed}");
        let trash_uri = trashed["data"]["object"]["uri"]
            .as_str()
            .unwrap_or_else(|| panic!("trash uri missing: {trashed}"));
        let gone = exchange(
            &object_bridge,
            serde_json::json!({
                "op": "delete_permanently",
                "principal_id": principal,
                "uri": trash_uri
            }),
        )
        .await;
        assert_eq!(gone["status"], "ok", "{target}: {gone}");
        let text = format!("{trashed}{gone}");
        assert!(!text.contains(&object_secret_hex), "{text}");
    }
    assert_eq!(std::fs::read(&object_key).unwrap(), object_secret);
    assert!(
        !runtime_did_file.exists(),
        "the confined helper must not create a runtime-did file"
    );
    object_bridge.shutdown().await.unwrap();
}
