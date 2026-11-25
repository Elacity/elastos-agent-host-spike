//! Real localhost and object binaries, started through the confined path.
//!
//! The rustc probe is not this proof. Run
//! `localhost_and_object_providers_work_inside_their_fences` on Linux as well
//! as macOS. The test lives in the library so it can store a signed auth
//! record. `server_infra` is the binary crate and cannot see that helper.

#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
use std::path::{Path, PathBuf};

/// The binary Cargo would hand an integration test of this package, or the
/// binary `just prepare-providers` built. This function does not run Cargo.
///
/// `localhost-provider` is a workspace member. `CARGO_BIN_EXE_localhost_provider`
/// is set for that package's own integration tests, not for `elastos-server`.
/// When it is unset, localhost is `target/fence-localhost-provider/debug/localhost-provider`.
/// Object is `target/provider-fence-tests/debug/object-provider`. A missing
/// file panics with the prepare instruction.
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
fn provider_binary(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Some(value) = std::env::var_os(&env_key) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return path;
        }
        panic!("{env_key} is set but {} is not a file", path.display());
    }
    let repo = std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .expect("repo root");
    let target_dir = if name == "localhost-provider" {
        repo.join("target/fence-localhost-provider")
    } else {
        repo.join("target/provider-fence-tests")
    };
    let binary = target_dir.join("debug").join(name);
    if !binary.is_file() {
        panic!(
            "{name} is not at {}. Run `just prepare-providers` before these tests. That command builds the helper binaries; the tests do not download crates.",
            binary.display()
        );
    }
    binary
}

/// A name `just prepare-providers` does not build has no binary. The panic
/// names that command. The tests do not run Cargo to fill the gap.
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
#[test]
fn a_missing_helper_binary_names_prepare_providers() {
    let caught = std::panic::catch_unwind(|| provider_binary("not-a-helper"));
    let message = caught.expect_err("a missing helper binary panics");
    let text = message
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| message.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        text.contains("Run `just prepare-providers` before these tests.")
            && text.contains("the tests do not download crates."),
        "{text}"
    );
}

/// Localhost and object do their file job and cannot open the device key.
///
/// macOS also refuses lstat. Linux Landlock does not mediate stat, so the
/// localhost stat of `identity/device.key` is `ok` and must not carry the key
/// bytes. The read stays an error. Removing the fence makes that read succeed.
/// Object init decides by open on Linux and by open plus lstat on macOS. A
/// successful init means that check passed. The parent then checks the key
/// bytes are unchanged.
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
#[tokio::test]
async fn localhost_and_object_providers_work_inside_their_fences() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    fn helper_authority() -> elastos_common::ProviderAuthority {
        serde_json::from_value(serde_json::json!({
            "reason": "runtime grant",
            "capabilities": [],
            "audit_events": [],
            "rights": []
        }))
        .expect("full grant authority")
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
        &helper_authority(),
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
        &helper_authority(),
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

/// An old data directory has no helper capsule.json. The helpers still start
/// from the manifest in the binary, and a file that was already there stays
/// readable with the same mode and owner.
#[cfg(all(
    not(elastos_unsupported_os_check),
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
#[tokio::test]
async fn an_updated_home_reads_existing_files_through_the_fence() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn authority(raw: &str) -> elastos_common::ProviderAuthority {
        let manifest: elastos_common::CapsuleManifest = serde_json::from_str(raw).unwrap();
        manifest.authority.unwrap()
    }

    fn pinned(path: &Path, data_dir: &Path) -> elastos_runtime::provider::CheckedExecutable {
        let digest = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
        elastos_runtime::provider::CheckedExecutable::pinned(path, &format!("sha256:{digest}"))
            .unwrap()
            .with_home_data_dir(data_dir)
    }

    fn old_home(parent: &Path) -> PathBuf {
        let data = parent.join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(data.join("ElastOS")).unwrap();
        let file = data.join("ElastOS/kept.txt");
        std::fs::write(&file, b"kept-from-the-old-home").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!data.join("UsersAI").exists());
        assert!(!data
            .join("capsules/localhost-provider/capsule.json")
            .exists());
        elastos_common::localhost::ensure_file_backed_roots(&data).unwrap();
        let chain = data.join("chain-provider");
        // The old helper created this directory with create_dir_all and did
        // not force 0700. The start tightens the opened handle.
        std::fs::create_dir_all(&chain).unwrap();
        let chain_file = chain.join("kept.txt");
        std::fs::write(&chain_file, b"kept-from-the-old-home").unwrap();
        std::fs::set_permissions(&chain_file, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::canonicalize(&data).unwrap_or(data)
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

    async fn read_localhost(data: &Path) {
        let file = data.join("ElastOS/kept.txt");
        let before = std::fs::symlink_metadata(&file).unwrap();
        let binary = provider_binary("localhost-provider");
        let confined = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
            "localhost-provider",
            &authority(include_str!(
                "../../../capsules/localhost-provider/capsule.json"
            )),
            &pinned(&binary, data),
            data,
            elastos_runtime::provider::BridgeProviderConfig {
                base_path: data.display().to_string(),
                allowed_paths: vec!["*".to_string()],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|err| panic!("localhost at {}: {err}", data.display()));
        let bridge = confined.bridge().clone();
        let read = exchange(
            &bridge,
            serde_json::json!({
                "op": "read",
                "path": "ElastOS/kept.txt",
                "encoding": "utf8"
            }),
        )
        .await;
        assert_eq!(read["status"], "ok", "{read}");
        assert_eq!(read["data"]["content"], "kept-from-the-old-home");
        let after = std::fs::symlink_metadata(&file).unwrap();
        assert_eq!(after.mode() & 0o777, 0o640);
        assert_eq!(after.uid(), before.uid());
        assert_eq!(std::fs::read(&file).unwrap(), b"kept-from-the-old-home");
        bridge.shutdown().await.unwrap();
    }

    let held = tempfile::tempdir().unwrap();
    let data = old_home(held.path());
    read_localhost(&data).await;

    let principal = "person:local:ada";
    let record = crate::auth::store_test_human_principal(&data, principal);
    let relative = record.localhost_root.trim_start_matches("localhost://");
    let object_file = data.join(relative).join("kept.txt");
    std::fs::create_dir_all(object_file.parent().unwrap()).unwrap();
    std::fs::write(&object_file, b"kept-from-the-old-home").unwrap();
    std::fs::set_permissions(&object_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let object_before = std::fs::symlink_metadata(&object_file).unwrap();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object_bin = provider_binary("object-provider");
    let object = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "object-provider",
        &authority(include_str!(
            "../../../../capsules/object-provider/capsule.json"
        )),
        &pinned(&object_bin, &data),
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            extra: serde_json::json!({ "runtime_did": did }),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("object init failed: {err}"));
    let object_bridge = object.bridge().clone();
    let object_read = exchange(
        &object_bridge,
        serde_json::json!({
            "op": "read",
            "principal_id": principal,
            "uri": format!("{}/kept.txt", record.localhost_root)
        }),
    )
    .await;
    assert_eq!(object_read["status"], "ok", "{object_read}");
    let object_after = std::fs::symlink_metadata(&object_file).unwrap();
    assert_eq!(object_after.mode() & 0o777, 0o640);
    assert_eq!(object_after.uid(), object_before.uid());
    object_bridge.shutdown().await.unwrap();

    let chain_file = data.join("chain-provider/kept.txt");
    let chain_before = std::fs::symlink_metadata(&chain_file).unwrap();
    let chain_bin = provider_binary("chain-provider");
    let chain = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "chain-provider",
        &authority(include_str!(
            "../../../../capsules/chain-provider/capsule.json"
        )),
        &pinned(&chain_bin, &data),
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("chain init failed: {err}"));
    let chain_bridge = chain.bridge().clone();
    let networks = exchange(&chain_bridge, serde_json::json!({"op": "networks"})).await;
    let networks_text = networks.to_string();
    assert!(
        networks_text.contains("ok")
            || networks.get("status").and_then(|v| v.as_str()) == Some("ok"),
        "{networks}"
    );
    let chain_after = std::fs::symlink_metadata(&chain_file).unwrap();
    assert_eq!(chain_after.mode() & 0o777, 0o640);
    assert_eq!(chain_after.uid(), chain_before.uid());
    assert_eq!(
        std::fs::read(&chain_file).unwrap(),
        b"kept-from-the-old-home"
    );
    chain_bridge.shutdown().await.unwrap();

    let link_hold = tempfile::tempdir().unwrap();
    let link = std::fs::canonicalize(link_hold.path())
        .unwrap()
        .join("home");
    std::os::unix::fs::symlink(&data, &link).unwrap();
    read_localhost(&link).await;

    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let tmp_data = old_home(tmp.path());
    let canonical = std::fs::canonicalize(&tmp_data).unwrap();
    assert!(
        canonical.starts_with("/tmp") || canonical.starts_with("/private/tmp"),
        "{}",
        canonical.display()
    );
    read_localhost(&tmp_data).await;

    let root_dev = std::fs::metadata("/").unwrap().dev();
    let mut other = None;
    for mount in ["/Volumes", "/mnt", "/media"] {
        let Ok(entries) = std::fs::read_dir(mount) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_dir() || meta.dev() == root_dev {
                continue;
            }
            let Ok(dir) = tempfile::tempdir_in(&path) else {
                continue;
            };
            let probe = dir.path().join("mode-probe");
            if std::fs::write(&probe, b"mode").is_err() {
                continue;
            }
            if std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).is_err() {
                continue;
            }
            let Ok(probed) = std::fs::symlink_metadata(&probe) else {
                continue;
            };
            if probed.mode() & 0o777 != 0o640 {
                continue;
            }
            eprintln!("other-volume-read {}", path.display());
            other = Some(dir);
            break;
        }
        if other.is_some() {
            break;
        }
    }
    if let Some(dir) = other {
        let data = old_home(dir.path());
        assert_ne!(std::fs::metadata(&data).unwrap().dev(), root_dev);
        read_localhost(&data).await;
        eprintln!("other-volume-read used {}", data.display());
    } else {
        eprintln!("other-volume-read none");
    }
}

/// Source and installed Homes both run `setup_server_infrastructure_impl`.
/// That function creates every file-backed root before the first helper spawn.
/// Chain's own directory is created inside `spawn_path_allow` before start.
#[test]
fn file_backed_roots_exist_before_the_first_helper_spawn() {
    let server = include_str!("server_infra.rs");
    let roots = server
        .find("ensure_file_backed_roots(&data_dir)")
        .expect("roots");
    let local = server
        .find("spawn_allow_listed_provider(\"localhost-provider\"")
        .expect("localhost");
    let object = server
        .find("spawn_allow_listed_provider(\"object-provider\"")
        .expect("object");
    let chain = server
        .find("spawn_allow_listed_provider(\"chain-provider\"")
        .expect("chain");
    assert!(roots < local && local < object && object < chain);
    let bridge = include_str!("../../elastos-runtime/src/provider/bridge.rs");
    let chain_root = bridge
        .find("Self::ensure_chain_provider_root(data_dir)")
        .expect("chain root");
    let start = bridge
        .find("super::os_entry::start_path_allow(")
        .expect("start");
    assert!(chain_root < start);
}
