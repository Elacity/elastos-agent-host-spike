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
            .unwrap_or_else(|err| panic!("helper request failed: {err}"))
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
    std::fs::write(
        data.join("config.toml"),
        format!("{} = true\n", crate::library::PROTECT_HOST_CONFIG_KEY),
    )
    .unwrap();
    std::fs::write(data.join("components.json"), b"{}\n").unwrap();
    for path in ["config.toml", "components.json"] {
        let answer = exchange(&bridge, serde_json::json!({"op": "read", "path": path})).await;
        assert_eq!(answer["status"], "error", "{path}: {answer}");
        assert!(data.join(path).is_file(), "{path}");
    }
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
            extra: crate::library::object_helper_init_extra(&did),
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
        with_object_authority(
            &object_data,
            serde_json::json!({
                "op": "write",
                "principal_id": principal,
                "uri": uri,
                "data": payload
            }),
        ),
    )
    .await;
    assert_eq!(object_wrote["status"], "ok", "{object_wrote}");
    let object_read = exchange(
        &object_bridge,
        with_object_authority(
            &object_data,
            serde_json::json!({"op": "read", "principal_id": principal, "uri": uri}),
        ),
    )
    .await;
    assert_eq!(object_read["status"], "ok", "{object_read}");
    assert_eq!(object_read["data"]["data"], payload);
    let folder = exchange(
        &object_bridge,
        with_object_authority(
            &object_data,
            serde_json::json!({
                "op": "mkdir",
                "principal_id": principal,
                "parent_uri": record.localhost_root,
                "name": "folder"
            }),
        ),
    )
    .await;
    assert_eq!(folder["status"], "ok", "{folder}");
    let folder_uri = format!("{}/folder", record.localhost_root);
    for target in [uri.as_str(), folder_uri.as_str()] {
        let trashed = exchange(
            &object_bridge,
            with_object_authority(
                &object_data,
                serde_json::json!({"op": "trash", "principal_id": principal, "uri": target}),
            ),
        )
        .await;
        assert_eq!(trashed["status"], "ok", "{target}: {trashed}");
        let trash_uri = trashed["data"]["object"]["uri"]
            .as_str()
            .unwrap_or_else(|| panic!("trash uri missing: {trashed}"));
        let gone = exchange(
            &object_bridge,
            with_object_authority(
                &object_data,
                serde_json::json!({
                    "op": "delete_permanently",
                    "principal_id": principal,
                    "uri": trash_uri
                }),
            ),
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
    recovery_kit_touch(&object_bin).await;
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
            .unwrap_or_else(|err| panic!("helper request failed: {err}"))
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
            extra: crate::library::object_helper_init_extra(&did),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("object init failed: {err}"));
    let object_bridge = object.bridge().clone();
    let object_read = exchange(
        &object_bridge,
        with_object_authority(
            &data,
            serde_json::json!({
                "op": "read",
                "principal_id": principal,
                "uri": format!("{}/kept.txt", record.localhost_root)
            }),
        ),
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
    recovery_kit_touch(&provider_binary("object-provider")).await;
}

/// Source and installed Homes both run `setup_server_infrastructure_impl`.
/// That function creates every file-backed root before the first helper spawn.
/// Chain's own directory is created inside `spawn_path_allow` before start.
/// Audit-checkpoint state is ready before the object helper starts.
/// Every Library object is under a principal root, `Users/<id>` or
/// `UsersAI/<id>`, so capsule storage roots are too. The object fence covers
/// both parents, and Home starts the object helper once.
#[test]
fn file_backed_roots_exist_before_the_first_helper_spawn() {
    let server = include_str!("server_infra.rs");
    let roots = server
        .find("ensure_file_backed_roots(&data_dir)")
        .expect("roots");
    let auth = server
        .find("verify_auth_audit_chain_ready(&data_dir)")
        .expect("auth checkpoint");
    let local = server
        .find("spawn_allow_listed_provider(\"localhost-provider\"")
        .expect("localhost");
    let object = server[local..]
        .find("spawn_allow_listed_provider(\"object-provider\"")
        .map(|i| local + i)
        .expect("object");
    let chain = server[object..]
        .find("spawn_allow_listed_provider(\"chain-provider\"")
        .map(|i| object + i)
        .expect("chain");
    assert!(roots < auth && auth < local && local < object && object < chain);
    assert_eq!(
        server
            .matches("spawn_allow_listed_provider(\"object-provider\"")
            .count(),
        1,
        "Home starts the object helper once; it does not restart it when storage roots change"
    );
    let path_allow = include_str!("../../elastos-runtime/src/provider/path_allow.rs");
    let object_roots = path_allow
        .split("const OBJECT_ROOTS")
        .nth(1)
        .and_then(|rest| rest.split("];").next())
        .expect("OBJECT_ROOTS");
    for parent in ["(\"Users\", \"Users\")", "(\"UsersAI\", \"UsersAI\")"] {
        assert!(
            object_roots.contains(parent),
            "the object fence must cover {parent}, the parent of every Library root"
        );
    }
    let bridge = include_str!("../../elastos-runtime/src/provider/bridge.rs");
    let chain_root = bridge
        .find("Self::ensure_chain_provider_root(data_dir)")
        .expect("chain root");
    let start = bridge
        .find("super::os_entry::start_path_allow(")
        .expect("start");
    assert!(chain_root < start);
}

/// Fresh Home data: audit checkpoint is ready before the object helper starts,
/// so the first Library roots call answers.
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
async fn fresh_data_dir_auth_ready_then_object_roots_answer() {
    let (_hold, data) = helper_data_root();
    assert!(
        !data.join("ElastOS/System/Auth").exists(),
        "fresh data must start without Auth"
    );
    crate::auth::verify_auth_audit_chain_ready(&data)
        .unwrap_or_else(|err| panic!("audit checkpoint was not ready: {err:#}"));
    assert!(
        data.join("ElastOS/System/Auth").is_dir(),
        "Host must create Auth before the object fence"
    );
    let principal = "person:local:ada";
    crate::auth::store_test_human_principal(&data, principal);
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    let roots = exchange_ok(
        &data,
        object.bridge(),
        serde_json::json!({"op": "roots", "principal_id": principal}),
    )
    .await;
    assert_eq!(roots["status"], "ok", "{roots}");
    assert!(
        roots["data"]["roots"]
            .as_array()
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        "roots must answer: {roots}"
    );
    object.bridge().shutdown().await.unwrap();
}

/// The object helper starts before the capsule is installed, as when Home is
/// already running. The new grant's root is under `Users`, which the fence
/// already covers, so the Library write lands without a helper restart.
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
async fn capsule_install_while_home_runs_writes_under_users_fence() {
    use base64::Engine;
    let (_hold, data) = helper_data_root();
    crate::auth::verify_auth_audit_chain_ready(&data)
        .unwrap_or_else(|err| panic!("audit checkpoint was not ready: {err:#}"));
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let root = protection.localhost_root;
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    let bridge = object.bridge();

    let capsule = data.join("capsules/notes");
    std::fs::create_dir_all(&capsule).unwrap();
    std::fs::write(
        capsule.join("index.html"),
        "<!doctype html><title>Notes</title>",
    )
    .unwrap();
    std::fs::write(
        capsule.join("capsule.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule/v1",
            "name": "notes",
            "version": "0.1.0",
            "description": "Notes",
            "author": "elastos",
            "role": "app",
            "type": "data",
            "entrypoint": "index.html",
            "permissions": { "storage": ["localhost://Users/self/Notes/*"] }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        data.join("components.json"),
        serde_json::to_vec(&serde_json::json!({
            "external": {
                "notes": { "install_path": "capsules/notes", "platforms": {} }
            },
            "capsules": {},
            "profiles": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let grants = crate::api::capsule_inventory::read_active_storage_grants(&data)
        .unwrap_or_else(|err| panic!("grant read: {err}"));
    assert!(
        grants.iter().any(|grant| grant.contains("Notes")),
        "installed grant missing: {grants:?}"
    );
    for grant in &grants {
        let path = elastos_common::localhost::rooted_localhost_fs_path(&data, grant)
            .unwrap_or_else(|| panic!("grant is not file-backed: {grant}"));
        let under_users =
            path.starts_with(data.join("Users")) || path.starts_with(data.join("UsersAI"));
        assert!(
            under_users,
            "every capsule storage root must live under Users or UsersAI: {grant} -> {}",
            path.display()
        );
    }

    let uri = format!("{root}/Notes/hello.txt");
    let payload = base64::engine::general_purpose::STANDARD.encode(b"hello after install");
    let wrote = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": payload
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    assert!(
        data.join(uri.trim_start_matches("localhost://")).is_file(),
        "write under the new grant must land without restarting the helper"
    );
    let read = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "read", "principal_id": principal, "uri": uri}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");
    assert_eq!(read["data"]["data"], payload);

    // The helper started before the install, keeps no grant list and cannot
    // read the install. Its depth bound still covers the new root: a path 16
    // folders below `Notes` is refused by name and nothing is written.
    let parent = format!(
        "{root}/Notes/{}",
        (1..=15)
            .map(|n| format!("{n:02}"))
            .collect::<Vec<_>>()
            .join("/")
    );
    let deep = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": parent,
            "name": "16"
        }),
    )
    .await;
    assert_eq!(deep["status"], "error", "{deep}");
    let message = deep["message"].as_str().unwrap_or("");
    assert!(
        message.contains("more than 16 folders deep") && message.contains("Notes"),
        "{deep}"
    );
    assert!(
        !data
            .join(format!("{parent}/16").trim_start_matches("localhost://"))
            .exists(),
        "mkdir wrote the deep folder"
    );
    crate::api::auth_gateway::verify_configured_principal_roots_ready(&data)
        .unwrap_or_else(|err| panic!("Home did not start: {err:#}"));
    let again = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": format!("{root}/Notes/again.txt"),
            "data": payload
        }),
    )
    .await;
    assert_eq!(again["status"], "ok", "{again}");
    bridge.shutdown().await.unwrap();
}

/// Library list through the fenced object-provider binary.
///
/// The helper cannot read `components.json`, `capsules`, or `config.toml`, so
/// its own reply has no viewer and no `protect`. The Runtime fills those
/// fields from the same data directory. Removing the fill makes this red.
/// The helper reply stays empty, which is the fence.
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
async fn fenced_object_library_list_gets_viewers_from_the_runtime() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    fn authority() -> elastos_common::ProviderAuthority {
        serde_json::from_value(serde_json::json!({
            "reason": "runtime grant",
            "capabilities": [],
            "audit_events": [],
            "rights": []
        }))
        .expect("full grant authority")
    }

    let temp = tempfile::tempdir().unwrap();
    let data = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in elastos_common::localhost::FILE_BACKED_ROOTS {
        let root = data.join(name);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        data.join("config.toml"),
        format!("{} = true\n", crate::library::PROTECT_HOST_CONFIG_KEY),
    )
    .unwrap();
    let capsule = data.join("capsules/documents");
    std::fs::create_dir_all(&capsule).unwrap();
    std::fs::write(
        capsule.join("index.html"),
        "<!doctype html><title>Documents</title>",
    )
    .unwrap();
    std::fs::write(
        capsule.join("capsule.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule/v1",
            "name": "documents",
            "version": "0.1.0",
            "description": "Documents",
            "author": "elastos",
            "role": "viewer",
            "type": "data",
            "entrypoint": "index.html"
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        data.join("components.json"),
        serde_json::to_vec(&serde_json::json!({
            "external": {
                "documents": { "install_path": "capsules/documents", "platforms": {} }
            },
            "capsules": {},
            "profiles": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let principal = "person:local:ada";
    let record = crate::auth::store_test_human_principal(&data, principal);
    let relative = record.localhost_root.trim_start_matches("localhost://");
    let note = data.join(relative).join("note.txt");
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, b"hello library").unwrap();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let binary = provider_binary("object-provider");
    let digest = hex::encode(Sha256::digest(std::fs::read(&binary).unwrap()));
    let checked =
        elastos_runtime::provider::CheckedExecutable::pinned(&binary, &format!("sha256:{digest}"))
            .unwrap()
            .with_home_data_dir(&data);
    let started = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "object-provider",
        &authority(),
        &checked,
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            extra: crate::library::object_helper_init_extra(&did),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("object init failed: {err}"));
    let listed = started
        .bridge()
        .send_raw(&with_object_authority(
            &data,
            serde_json::json!({
                "op": "list",
                "principal_id": principal,
                "uri": record.localhost_root
            }),
        ))
        .await
        .unwrap_or_else(|err| panic!("library list failed: {err}"));
    assert_eq!(listed["status"], "ok", "{listed}");
    let raw = listed["data"]["objects"]
        .as_array()
        .and_then(|objects| objects.iter().find(|object| object["name"] == "note.txt"))
        .cloned()
        .unwrap_or_else(|| panic!("note.txt missing from the fenced list: {listed}"));
    let raw_viewers = raw.get("viewers").and_then(|value| value.as_array());
    assert!(
        raw_viewers
            .map(|viewers| viewers.is_empty())
            .unwrap_or(true),
        "the fenced helper must not see the documents viewer: {raw}"
    );
    assert!(
        !raw["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cap| cap == "protect"),
        "the fenced helper must not see protect: {raw}"
    );
    let kept = raw.clone();
    let mut filled = listed;
    crate::library::fill_fenced_library_fields(&data, &mut filled);
    let object = filled["data"]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["name"] == "note.txt")
        .unwrap();
    assert_eq!(object["viewer"], "documents", "{object}");
    assert_eq!(object["viewers"][0]["id"], "documents");
    assert_eq!(object["viewers"][0]["label"], "Documents");
    assert!(
        object["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cap| cap == "protect"),
        "{object}"
    );
    for key in [
        "schema",
        "uri",
        "name",
        "kind",
        "mime",
        "size",
        "created_at",
        "modified_at",
        "revision",
        "availability",
        "content_cid",
        "metadata",
        "published",
        "shared",
    ] {
        assert_eq!(object[key], kept[key], "{key} changed: {object}");
    }
    let before = kept["capabilities"].as_array().unwrap();
    let after = object["capabilities"].as_array().unwrap();
    assert!(
        after.starts_with(before),
        "capabilities lost a field: {before:?} -> {after:?}"
    );
    started.bridge().shutdown().await.unwrap();
    recovery_kit_touch(&provider_binary("object-provider")).await;
}

/// Deleting the object fill after a provider send turns this red, including
/// a caller in a file this list did not name. A scheme variable compared with
/// "object" in the same window has to fill too.
#[test]
fn gateway_object_reply_calls_fill_fenced_library_fields() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut misses = Vec::new();
    scan_object_sends(&root, &mut misses);
    assert!(
        misses.is_empty(),
        "object send without fill_fenced_library_fields: {misses:?}"
    );
}

fn mask_rust_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut depth = 1;
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\n' {
                    i += 1;
                    continue;
                }
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    depth += 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    continue;
                }
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    continue;
                }
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    String::from_utf8(out).expect("masked source stays utf-8")
}

fn function_body(text: &str, signature_at: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut i = signature_at;
    while i < bytes.len() && bytes[i] != b'{' {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let start = i;
    let mut depth = 0i32;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'{' {
            depth += 1;
        }
        if bytes[i] == b'}' {
            depth -= 1;
            if depth == 0 {
                return text.get(start..=i);
            }
        }
        i += 1;
    }
    None
}

fn scan_object_sends(dir: &std::path::Path, misses: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan_object_sends(&path, misses);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = mask_rust_comments(&std::fs::read_to_string(&path).unwrap());
        let mut from = 0;
        while let Some(at) = text[from..].find("send_raw(") {
            let start = from + at;
            let end = text.floor_char_boundary(text.len().min(start + 2400));
            let window = &text[start..end];
            let head = window.find(')').map(|end| &window[..end]).unwrap_or(window);
            let literal = argument_is_object(head);
            let scheme = head.contains("&scheme") || head.contains("&dispatch.scheme");
            let object_scheme = scheme && window.contains("== \"object\"");
            if (literal || object_scheme) && !window.contains("fill_fenced_library_fields") {
                let line = text[..start].lines().count();
                misses.push(format!("{}:{line}", path.display()));
            }
            from = start + "send_raw(".len();
        }
    }
}

fn argument_is_object(head: &str) -> bool {
    let rest = head.trim_start_matches("send_raw(").trim_start();
    rest.starts_with("\"object\"")
}

/// Deleting `AttachedRequest::new`, `ObjectAuthorityV1::attach`, or
/// `attach_object_authority` before an object send turns this red.
/// A `ProviderRegistry` send is covered by `AuthorityAttachingProvider`
/// instead of a second attach at the call. The confined registration has
/// to name `AuthorityAttachingProvider` too.
#[test]
fn every_object_dispatch_path_carries_the_envelope() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut misses = Vec::new();
    let mut checked = 0usize;
    scan_object_authority(&root, &mut misses, &mut checked);
    assert!(
        misses.is_empty(),
        "object send without an authority envelope: {misses:?}"
    );
    assert!(checked > 0, "the envelope scan found no object send");
    let authority =
        mask_rust_comments(&std::fs::read_to_string(root.join("object_authority.rs")).unwrap());
    let dispatch_at = authority
        .find("async fn dispatch(")
        .expect("AuthorityAttachingProvider::dispatch");
    let dispatch = function_body(&authority, dispatch_at).expect("dispatch body");
    assert!(
        dispatch.contains("AttachedRequest::new"),
        "dispatch does not build an attached request"
    );
    let impl_at = authority
        .find("impl AttachedRequest")
        .expect("AttachedRequest");
    let new_at = authority[impl_at..]
        .find("fn new(")
        .map(|at| impl_at + at)
        .expect("AttachedRequest::new");
    let new_body = function_body(&authority, new_at).expect("AttachedRequest::new body");
    assert!(
        new_body.contains("ObjectAuthorityV1::attach"),
        "AttachedRequest::new does not attach the runtime envelope"
    );
    let registration = std::fs::read_to_string(root.join("server_infra.rs")).unwrap();
    assert!(
        registration.contains("AuthorityAttachingProvider::new"),
        "confined object registration does not attach an authority envelope"
    );
}

fn scan_object_authority(dir: &std::path::Path, misses: &mut Vec<String>, checked: &mut usize) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan_object_authority(&path, misses, checked);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = mask_rust_comments(&std::fs::read_to_string(&path).unwrap());
        let marker = concat!("send_raw", "(");
        let mut from = 0;
        while let Some(at) = text[from..].find(marker) {
            let start = from + at;
            let end = text.floor_char_boundary(text.len().min(start + 2400));
            let window = &text[start..end];
            let head = window.find(')').map(|end| &window[..end]).unwrap_or(window);
            let literal = argument_is_object(head);
            let scheme = head.contains("&scheme") || head.contains("&dispatch.scheme");
            let object_scheme = scheme && window.contains("== \"object\"");
            if literal || object_scheme {
                *checked += 1;
                let back = text.floor_char_boundary(start.saturating_sub(2500));
                // A provider-registry send reaches AuthorityAttachingProvider,
                // which inserts the Runtime envelope. The dispatch body must
                // call AttachedRequest::new, and that constructor must attach.
                if !registry_object_send(&text[..start])
                    && !carries_object_authority(&text[back..start])
                {
                    let line = text[..start].lines().count();
                    misses.push(format!("{}:{line}", path.display()));
                }
            }
            from = start + marker.len();
        }
    }
}

fn carries_object_authority(before: &str) -> bool {
    before.contains("ObjectAuthorityV1::attach")
        || before.contains("AttachedRequest::new")
        || before.contains("attach_object_authority(")
}

/// `registry.send_raw("object")` and a registry field split across lines.
/// The registered object provider is `AuthorityAttachingProvider`.
fn registry_object_send(before: &str) -> bool {
    let tail = before.trim_end().trim_end_matches('.').trim_end();
    tail.ends_with("registry")
}

/// Release musl helpers, started by `spawn_path_allow` on Linux. The CI step
/// sets `ELASTOS_MUSL_HELPER_FENCE` and the three binary paths. A normal
/// `cargo test` leaves the flag unset and does not look for those binaries.
#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn musl_release_helpers_start_under_the_fence() {
    if std::env::var_os("ELASTOS_MUSL_HELPER_FENCE").is_none() {
        return;
    }
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn binary(key: &str) -> PathBuf {
        let path = std::env::var(key).unwrap_or_else(|_| panic!("{key} is unset"));
        let path = PathBuf::from(path);
        assert!(path.is_file(), "{} is not the musl helper", path.display());
        path
    }

    fn pinned(path: &Path, data: &Path) -> elastos_runtime::provider::CheckedExecutable {
        let digest = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
        elastos_runtime::provider::CheckedExecutable::pinned(path, &format!("sha256:{digest}"))
            .unwrap()
            .with_home_data_dir(data)
    }

    fn authority() -> elastos_common::ProviderAuthority {
        serde_json::from_value(serde_json::json!({
            "reason": "runtime grant",
            "capabilities": [],
            "audit_events": [],
            "rights": []
        }))
        .unwrap()
    }

    async fn exchange(
        data: &Path,
        bridge: &elastos_runtime::provider::ProviderBridge,
        request: serde_json::Value,
    ) -> serde_json::Value {
        let request = if request.get("principal_id").is_some() {
            with_object_authority(data, request)
        } else {
            request
        };
        bridge
            .send_raw(&request)
            .await
            .unwrap_or_else(|err| panic!("helper request failed: {err}"))
    }

    let localhost_bin = binary("ELASTOS_MUSL_LOCALHOST");
    let object_bin = binary("ELASTOS_MUSL_OBJECT");
    let chain_bin = binary("ELASTOS_MUSL_CHAIN");

    let home = tempfile::tempdir().unwrap();
    let data = std::fs::canonicalize(home.path()).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in elastos_common::localhost::FILE_BACKED_ROOTS {
        let root = data.join(name);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(data.join("ElastOS/musl-note.txt"), b"musl-localhost").unwrap();
    let localhost = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "localhost-provider",
        &authority(),
        &pinned(&localhost_bin, &data),
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("musl localhost init failed: {err}"));
    let read = exchange(
        &data,
        localhost.bridge(),
        serde_json::json!({"op": "read", "path": "ElastOS/musl-note.txt"}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");

    // A 4 MiB read is its own musl mallocng group. Freeing it calls munmap.
    // Eight reads that keep the mapping grow the helper by tens of mebibytes.
    let bulk = data.join("ElastOS/bulk.bin");
    {
        let mut file = std::fs::File::create(&bulk).unwrap();
        let chunk = vec![b'a'; 1024 * 1024];
        for _ in 0..4 {
            file.write_all(&chunk).unwrap();
        }
    }
    fn resident_kib(binary: &Path) -> u64 {
        let want = std::fs::metadata(binary).unwrap();
        let want_path = std::fs::canonicalize(binary).unwrap();
        let mut matches = Vec::new();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(|ch| ch.is_ascii_digit())
            {
                continue;
            }
            let exe = entry.path().join("exe");
            let same_file = std::fs::metadata(&exe)
                .map(|meta| meta.dev() == want.dev() && meta.ino() == want.ino())
                .unwrap_or(false);
            let same_path = std::fs::read_link(&exe)
                .map(|path| path == want_path || path == binary)
                .unwrap_or(false);
            if !same_file && !same_path {
                continue;
            }
            let status = std::fs::read_to_string(entry.path().join("status")).unwrap_or_default();
            let kib = status.lines().find_map(|line| {
                let rest = line.strip_prefix("VmRSS:")?;
                rest.split_whitespace().next()?.parse::<u64>().ok()
            });
            if let Some(kib) = kib {
                matches.push(kib);
            }
        }
        assert_eq!(
            matches.len(),
            1,
            "localhost helper resident set: {matches:?}"
        );
        matches[0]
    }
    let warm = exchange(
        &data,
        localhost.bridge(),
        serde_json::json!({
            "op": "read",
            "path": "ElastOS/bulk.bin",
            "encoding": "utf8"
        }),
    )
    .await;
    assert_eq!(warm["status"], "ok", "{warm}");
    assert_eq!(warm["data"]["size"], 4 * 1024 * 1024, "{warm}");
    drop(warm);
    let before = resident_kib(&localhost_bin);
    for _ in 0..8 {
        let got = exchange(
            &data,
            localhost.bridge(),
            serde_json::json!({
                "op": "read",
                "path": "ElastOS/bulk.bin",
                "encoding": "utf8"
            }),
        )
        .await;
        assert_eq!(got["status"], "ok", "{got}");
        assert_eq!(got["data"]["size"], 4 * 1024 * 1024);
    }
    let after = resident_kib(&localhost_bin);
    assert!(
        after.saturating_sub(before) < 16 * 1024,
        "localhost resident grew from {before} KiB to {after} KiB"
    );
    std::fs::create_dir_all(data.join("ElastOS/tree/nested")).unwrap();
    std::fs::write(data.join("ElastOS/tree/nested/leaf.txt"), b"leaf").unwrap();
    let deleted = exchange(
        &data,
        localhost.bridge(),
        serde_json::json!({
            "op": "delete",
            "path": "ElastOS/tree",
            "recursive": true
        }),
    )
    .await;
    assert_eq!(deleted["status"], "ok", "{deleted}");
    assert!(
        !data.join("ElastOS/tree").exists(),
        "localhost left the tree"
    );
    localhost.bridge().shutdown().await.unwrap();

    std::fs::remove_dir_all(data.join("ElastOS")).unwrap();
    assert!(!data.join("ElastOS").exists());
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    assert!(
        !data.join("ElastOS/System").exists(),
        "the object proof starts with no ElastOS/System directory"
    );
    let object = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "object-provider",
        &authority(),
        &pinned(&object_bin, &data),
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            extra: crate::library::object_helper_init_extra(&did),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("musl object init failed: {err}"));
    assert!(
        data.join("ElastOS/System").is_dir(),
        "piece 2 still grants ElastOS/System, so object start creates the sign-in parent; piece 3 removes that root"
    );
    assert!(
        data.join("ElastOS/SystemServices/Library").is_dir(),
        "object start creates the Library index"
    );
    let principal = "person:local:ada";
    let record = crate::auth::store_test_human_principal(&data, principal);
    let bridge = object.bridge();
    let uri = format!("{}/note.txt", record.localhost_root);
    let payload = base64::engine::general_purpose::STANDARD.encode(b"musl-object");
    let wrote = exchange(
        &data,
        bridge,
        serde_json::json!({"op": "write", "principal_id": principal, "uri": uri, "data": payload}),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    let listed = exchange(
        &data,
        bridge,
        serde_json::json!({"op": "list", "principal_id": principal, "uri": record.localhost_root}),
    )
    .await;
    assert_eq!(listed["status"], "ok", "{listed}");
    let read = exchange(
        &data,
        bridge,
        serde_json::json!({"op": "read", "principal_id": principal, "uri": uri}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");
    let renamed = exchange(
        &data,
        bridge,
        serde_json::json!({"op": "rename", "principal_id": principal, "uri": uri, "name": "renamed.txt"}),
    )
    .await;
    assert_eq!(renamed["status"], "ok", "{renamed}");
    let renamed_uri = format!("{}/renamed.txt", record.localhost_root);
    let folder = exchange(
        &data,
        bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": record.localhost_root,
            "name": "tree"
        }),
    )
    .await;
    assert_eq!(folder["status"], "ok", "{folder}");
    let child = format!("{}/tree/child.txt", record.localhost_root);
    let child_wrote = exchange(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": child,
            "data": payload
        }),
    )
    .await;
    assert_eq!(child_wrote["status"], "ok", "{child_wrote}");
    let folder_uri = format!("{}/tree", record.localhost_root);
    let trashed = exchange(
        &data,
        bridge,
        serde_json::json!({"op": "trash", "principal_id": principal, "uri": folder_uri}),
    )
    .await;
    assert_eq!(trashed["status"], "ok", "{trashed}");
    let trash_uri = trashed["data"]["object"]["uri"]
        .as_str()
        .unwrap_or_else(|| panic!("trash uri missing: {trashed}"));
    let removed = exchange(
        &data,
        bridge,
        serde_json::json!({
            "op": "delete_permanently",
            "principal_id": principal,
            "uri": trash_uri
        }),
    )
    .await;
    assert_eq!(removed["status"], "ok", "{removed}");
    let mut zip_bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        writer
            .start_file("note.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"preview-text").unwrap();
        writer.finish().unwrap();
    }
    let archive_uri = format!("{}/notes.zip", record.localhost_root);
    let archive_data = base64::engine::general_purpose::STANDARD.encode(&zip_bytes);
    let archived = exchange(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": archive_uri,
            "data": archive_data
        }),
    )
    .await;
    assert_eq!(archived["status"], "ok", "{archived}");
    let preview = exchange(
        &data,
        bridge,
        serde_json::json!({
            "op": "archive_preview_entry",
            "principal_id": principal,
            "uri": archive_uri,
            "entry": "note.txt"
        }),
    )
    .await;
    assert_eq!(preview["status"], "ok", "{preview}");
    let _ = renamed_uri;
    bridge.shutdown().await.unwrap();

    let chain = elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "chain-provider",
        &authority(),
        &pinned(&chain_bin, &data),
        &data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            extra: serde_json::json!({
                "networks": [{
                    "id": "dns-probe",
                    "display_name": "DNS Probe",
                    "kind": "evm_json_rpc",
                    "chain_id": 1,
                    "native_symbol": "ETH",
                    "provider": "probe",
                    "mainnet": false,
                    "explorer_url": null,
                    "rpc_url": "https://musl-fence.invalid/rpc"
                }]
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("musl chain init failed: {err}"));
    let listed = exchange(&data, chain.bridge(), serde_json::json!({"op": "networks"})).await;
    assert_eq!(
        listed["status"], "ok",
        "musl chain networks after start: {listed}"
    );
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let loopback_nameserver = resolv.lines().any(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some("nameserver")
            && parts.next().is_some_and(|addr| addr.starts_with("127."))
    });
    if !loopback_nameserver {
        eprintln!(
            "musl fence: this machine has no loopback nameserver, so the chain DNS leg is not run"
        );
    } else {
        let lookup = exchange(
            &data,
            chain.bridge(),
            serde_json::json!({"op": "status", "network": "dns-probe"}),
        )
        .await;
        let lookup_text = lookup.to_string().to_lowercase();
        assert!(
            !lookup_text.contains("permission denied")
                && !lookup_text.contains("operation not permitted")
                && !lookup_text.contains("bad system call"),
            "chain name lookup was refused by the filter: {lookup}"
        );
        let again = exchange(&data, chain.bridge(), serde_json::json!({"op": "networks"})).await;
        assert_eq!(
            again["status"], "ok",
            "chain stayed up after the lookup: {again}"
        );
    }
    chain.bridge().shutdown().await.unwrap();
    recovery_kit_round_trip(&object_bin).await;
    eprintln!("musl helper fence: started");
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn helper_authority() -> elastos_common::ProviderAuthority {
    serde_json::from_value(serde_json::json!({
        "reason": "runtime grant",
        "capabilities": [],
        "audit_events": [],
        "rights": []
    }))
    .expect("full grant authority")
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn pinned_helper(path: &Path, data_dir: &Path) -> elastos_runtime::provider::CheckedExecutable {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
    elastos_runtime::provider::CheckedExecutable::pinned(path, &format!("sha256:{digest}"))
        .unwrap()
        .with_home_data_dir(data_dir)
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn helper_data_root() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
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

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn recovery_key_path(data: &Path) -> PathBuf {
    data.join("ElastOS/System/Auth/recovery-archive.key")
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn auth_record_paths(data: &Path) -> (PathBuf, PathBuf) {
    let dir = data.join("ElastOS/System/Auth");
    (
        dir.join("auth-state.json"),
        dir.join("audit-chain-required.json"),
    )
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn with_object_authority(data: &Path, request: serde_json::Value) -> serde_json::Value {
    crate::object_authority::ObjectAuthorityV1::attach(data, &request)
        .unwrap_or_else(|err| panic!("object authority: {err}"))
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn exchange_ok(
    data: &Path,
    bridge: &elastos_runtime::provider::ProviderBridge,
    request: serde_json::Value,
) -> serde_json::Value {
    let request = match crate::object_authority::ObjectAuthorityV1::attach(data, &request) {
        Ok(request) => request,
        Err(err) => {
            return serde_json::json!({
                "status": "error",
                "code": "library_error",
                "message": err.to_string(),
            })
        }
    };
    bridge
        .send_raw(&request)
        .await
        .unwrap_or_else(|err| panic!("object helper request failed: {err}"))
}

#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn spawn_object(
    binary: &Path,
    data: &Path,
    did: &str,
) -> elastos_runtime::provider::Confined {
    elastos_runtime::provider::ProviderBridge::spawn_path_allow(
        "object-provider",
        &helper_authority(),
        &pinned_helper(binary, data),
        data,
        elastos_runtime::provider::BridgeProviderConfig {
            base_path: data.display().to_string(),
            extra: crate::library::object_helper_init_extra(did),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|err| panic!("object init failed: {err}"))
}

/// Publish, rename, move, and share of a published file go through the fenced
/// object helper. Unpublish runs in the Runtime. A restart reconciles from the
/// records, so a withdrawn file stays withdrawn. The Home already has a
/// Recovery Kit.
#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[tokio::test]
async fn fenced_library_publish_rename_move_share_survive_restart() {
    use async_trait::async_trait;
    use base64::Engine;
    use elastos_runtime::provider::{
        Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    struct RecordingContent;

    #[async_trait]
    impl Provider for RecordingContent {
        async fn handle(
            &self,
            _request: ResourceRequest,
        ) -> Result<ResourceResponse, ProviderError> {
            Err(ProviderError::Provider("raw requests only".into()))
        }
        fn schemes(&self) -> Vec<&'static str> {
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "recording-content"
        }
        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> Result<serde_json::Value, ProviderError> {
            let cid = match request["op"].as_str() {
                Some("publish") => {
                    let digest = Sha256::digest(request["data"].as_str().unwrap_or_default());
                    format!("bafytest{}", &hex::encode(digest)[..16])
                }
                _ => request["cid"].as_str().unwrap_or_default().to_string(),
            };
            let status = if request["op"] == "unpublish" {
                "local_unpinned"
            } else {
                "local_pinned"
            };
            Ok(serde_json::json!({
                "status": "ok",
                "data": {
                    "cid": cid,
                    "availability": { "status": status },
                    "receipt": { "status": status },
                }
            }))
        }
    }

    /// The record file name is the sha256 of the document URI. The file body is
    /// an encrypted principal-root object, so the document URI is this name.
    fn record_names(data: &Path, root: &str) -> std::collections::BTreeSet<String> {
        let rel = root.trim_start_matches("localhost://");
        let dir = data
            .join(rel)
            .join(".AppData/LocalHost/.Runtime/Library/Published");
        let mut names = std::collections::BTreeSet::new();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return names;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                names.insert(stem.to_string());
            }
        }
        names
    }

    fn record_id(uri: &str) -> String {
        hex::encode(Sha256::digest(uri.as_bytes()))
    }

    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let root = protection.localhost_root;
    let key = recovery_key_path(&data);
    let key_bytes = std::fs::read(&key).unwrap();
    assert_eq!(key_bytes.len(), 32);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let binary = provider_binary("object-provider");
    let object = spawn_object(&binary, &data, &did).await;
    let library = data.join("ElastOS/SystemServices/Library");
    assert_eq!(
        file_mode(&library),
        0o700,
        "the index directory is owner-only"
    );
    assert!(
        !data.join("ElastOS/SystemServices/Wallet").exists(),
        "the object helper does not create Wallet"
    );
    let bridge = object.bridge();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", Arc::new(RecordingContent))
        .await
        .unwrap();
    let payload = base64::engine::general_purpose::STANDARD.encode(b"published-bytes");

    async fn runtime(
        data: &Path,
        registry: &Arc<ProviderRegistry>,
        principal: &str,
        op: &str,
        uri: &str,
    ) -> serde_json::Value {
        crate::library::handle_object_provider_runtime_request(
            data,
            registry.clone(),
            &serde_json::json!({
                "op": op,
                "principal_id": principal,
                "uri": uri,
            }),
        )
        .await
    }

    async fn stat(
        data: &Path,
        bridge: &elastos_runtime::provider::ProviderBridge,
        principal: &str,
        uri: &str,
    ) -> serde_json::Value {
        exchange_ok(
            data,
            bridge,
            serde_json::json!({
                "op": "stat",
                "principal_id": principal,
                "uri": uri,
            }),
        )
        .await
    }

    let mut cids = Vec::new();
    let mut withdrawn_at = Vec::new();
    for (name, op) in [
        ("rename.txt", "rename"),
        ("move.txt", "move"),
        ("share.txt", "share"),
    ] {
        let uri = format!("{root}/{name}");
        let wrote = exchange_ok(
            &data,
            bridge,
            serde_json::json!({
                "op": "write",
                "principal_id": principal,
                "uri": uri,
                "data": payload,
            }),
        )
        .await;
        assert_eq!(wrote["status"], "ok", "{name}: {wrote}");
        if name == "rename.txt" {
            assert_eq!(
                file_mode(&key),
                0o600,
                "the Runtime narrows the recovery key"
            );
        }
        let published = runtime(&data, &registry, principal, "publish", &uri).await;
        assert_eq!(published["status"], "ok", "{name}: {published}");
        let cid = published["data"]["cid"].as_str().unwrap().to_string();
        let saw = stat(&data, bridge, principal, &uri).await;
        assert_eq!(
            saw["data"]["object"]["publication"]["cid"], cid,
            "{name}: {saw}"
        );
        assert!(
            record_names(&data, &root).contains(&record_id(&uri)),
            "{name} record missing"
        );
        let (dest, answer) = match op {
            "rename" => {
                let answer = exchange_ok(
                    &data,
                    bridge,
                    serde_json::json!({
                        "op": "rename",
                        "principal_id": principal,
                        "uri": uri,
                        "name": "renamed.txt",
                    }),
                )
                .await;
                (format!("{root}/renamed.txt"), answer)
            }
            "move" => {
                let folder = exchange_ok(
                    &data,
                    bridge,
                    serde_json::json!({
                        "op": "mkdir",
                        "principal_id": principal,
                        "parent_uri": root,
                        "name": "Moved",
                    }),
                )
                .await;
                assert_eq!(folder["status"], "ok", "{folder}");
                let answer = exchange_ok(
                    &data,
                    bridge,
                    serde_json::json!({
                        "op": "move",
                        "principal_id": principal,
                        "uri": uri,
                        "target_parent_uri": format!("{root}/Moved"),
                    }),
                )
                .await;
                (format!("{root}/Moved/{name}"), answer)
            }
            "share" => {
                let answer = exchange_ok(
                    &data,
                    bridge,
                    serde_json::json!({
                        "op": "share",
                        "principal_id": principal,
                        "uri": uri,
                        "recipients": [],
                    }),
                )
                .await;
                (uri.clone(), answer)
            }
            _ => unreachable!(),
        };
        assert_eq!(answer["status"], "ok", "{name}: {answer}");
        assert_eq!(
            answer["data"]["object"]["publication"]["cid"], cid,
            "{answer}"
        );
        if op == "share" {
            assert_eq!(answer["data"]["policy"], "public_link", "{answer}");
        }
        let names = record_names(&data, &root);
        assert!(
            names.contains(&record_id(&dest)),
            "{name} has no record at {dest}"
        );
        if dest != uri {
            assert!(
                !names.contains(&record_id(&uri)),
                "{name} left a record at {uri}"
            );
        }
        let withdrawn = runtime(&data, &registry, principal, "unpublish", &dest).await;
        assert_eq!(withdrawn["status"], "ok", "{name}: {withdrawn}");
        let after = stat(&data, bridge, principal, &dest).await;
        assert!(
            after["data"]["object"]["publication"].is_null(),
            "{name} still published: {after}"
        );
        assert!(!crate::library::cid_is_published_here(&data, &cid));
        cids.push(cid);
        withdrawn_at.push(dest);
    }
    assert_eq!(file_mode(&key), 0o600);
    assert_eq!(std::fs::read(&key).unwrap(), key_bytes);
    bridge.shutdown().await.unwrap();
    crate::library::reconcile_published_cids(&data);
    for cid in &cids {
        assert!(!crate::library::cid_is_published_here(&data, cid), "{cid}");
    }
    let restarted = spawn_object(&binary, &data, &did).await;
    crate::library::reconcile_published_cids(&data);
    let again = restarted.bridge();
    for (cid, dest) in cids.iter().zip(withdrawn_at.iter()) {
        assert!(
            !crate::library::cid_is_published_here(&data, cid),
            "withdrawn after restart: {cid}"
        );
        let saw = stat(&data, again, principal, dest).await;
        assert!(
            saw["data"]["object"]["publication"].is_null(),
            "withdrawn file published again: {saw}"
        );
    }
    assert_eq!(std::fs::read(&key).unwrap(), key_bytes);
    again.shutdown().await.unwrap();
}

/// One write and one read with a Recovery Kit already on disk. The key is
/// widened to 0644 first. The helper reads it and leaves that mode.
#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn recovery_kit_touch(binary: &Path) {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let key = recovery_key_path(&data);
    assert!(key.is_file(), "the kit stores recovery-archive.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(binary, &data, &did).await;
    let bridge = object.bridge();
    let uri = format!("{}/kit.txt", protection.localhost_root);
    let payload = base64::engine::general_purpose::STANDARD.encode(b"kit");
    let wrote = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": payload
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    let read = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "read", "principal_id": principal, "uri": uri}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");
    assert_eq!(read["data"]["data"], payload);
    assert_eq!(
        file_mode(&key),
        0o600,
        "the Runtime narrows the recovery key"
    );
    assert_eq!(std::fs::read(&key).unwrap().len(), 32);
    bridge.shutdown().await.unwrap();
}

/// Protected root, key present and then created by the helper. List, read,
/// write, rename, delete, archive preview, and the desktop list the summary
/// sends all go through the fenced object helper.
#[cfg(any(
    all(not(elastos_unsupported_os_check), target_os = "macos"),
    all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn recovery_kit_round_trip(binary: &Path) {
    use base64::Engine;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let root = protection.localhost_root;
    let key = recovery_key_path(&data);
    let key_before = std::fs::read(&key).unwrap();
    assert_eq!(key_before.len(), 32);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(binary, &data, &did).await;
    let bridge = object.bridge();
    let payload = base64::engine::general_purpose::STANDARD.encode(b"protected");
    let note = format!("{root}/note.txt");
    let listed = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "list", "principal_id": principal, "uri": root}),
    )
    .await;
    assert_eq!(listed["status"], "ok", "{listed}");
    let wrote = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": note,
            "data": payload
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    assert_eq!(
        file_mode(&key),
        0o600,
        "the Runtime narrows the recovery key"
    );
    assert_eq!(std::fs::read(&key).unwrap(), key_before);
    let read = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "read", "principal_id": principal, "uri": note}),
    )
    .await;
    assert_eq!(read["status"], "ok", "{read}");
    assert_eq!(read["data"]["data"], payload);
    let renamed = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "rename",
            "principal_id": principal,
            "uri": note,
            "name": "renamed.txt"
        }),
    )
    .await;
    assert_eq!(renamed["status"], "ok", "{renamed}");
    let renamed_uri = format!("{root}/renamed.txt");
    let trashed = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "trash", "principal_id": principal, "uri": renamed_uri}),
    )
    .await;
    assert_eq!(trashed["status"], "ok", "{trashed}");
    let trash_uri = trashed["data"]["object"]["uri"]
        .as_str()
        .unwrap_or_else(|| panic!("trash uri missing: {trashed}"));
    let deleted = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "delete_permanently",
            "principal_id": principal,
            "uri": trash_uri
        }),
    )
    .await;
    assert_eq!(deleted["status"], "ok", "{deleted}");
    let mut zip_bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        writer
            .start_file("note.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"preview-text").unwrap();
        writer.finish().unwrap();
    }
    let archive_uri = format!("{root}/notes.zip");
    let archived = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": archive_uri,
            "data": base64::engine::general_purpose::STANDARD.encode(&zip_bytes)
        }),
    )
    .await;
    assert_eq!(archived["status"], "ok", "{archived}");
    let preview = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "archive_preview_entry",
            "principal_id": principal,
            "uri": archive_uri,
            "entry": "note.txt"
        }),
    )
    .await;
    assert_eq!(preview["status"], "ok", "{preview}");
    let desktop = format!("{root}/Desktop");
    let made = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": root,
            "name": "Desktop"
        }),
    )
    .await;
    assert_eq!(made["status"], "ok", "{made}");
    let desk = format!("{desktop}/desk.txt");
    let desk_wrote = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": desk,
            "data": payload
        }),
    )
    .await;
    assert_eq!(desk_wrote["status"], "ok", "{desk_wrote}");
    let summary = exchange_ok(
        &data,
        bridge,
        serde_json::json!({"op": "list", "principal_id": principal, "uri": desktop}),
    )
    .await;
    assert_eq!(summary["status"], "ok", "{summary}");
    assert!(
        summary.to_string().contains("desk.txt"),
        "desktop summary list missed the file: {summary}"
    );
    std::fs::remove_file(&key).unwrap();
    assert!(!key.exists());
    let missing = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": format!("{root}/after-key.txt"),
            "data": payload
        }),
    )
    .await;
    let missing_text = missing.to_string();
    assert_ne!(missing["status"], "ok", "{missing}");
    assert!(
        missing_text.contains(crate::object_authority::RECOVERY_KEY_REFUSAL),
        "{missing}"
    );
    assert!(!key.exists(), "the helper created the recovery key");
    std::fs::write(&key, &key_before).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let created = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": format!("{root}/after-key.txt"),
            "data": payload
        }),
    )
    .await;
    assert_eq!(created["status"], "ok", "{created}");
    assert_eq!(
        file_mode(&key),
        0o600,
        "the Runtime narrows the recovery key"
    );
    assert_eq!(std::fs::read(&key).unwrap(), key_before);
    let created_read = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "read",
            "principal_id": principal,
            "uri": format!("{root}/after-key.txt")
        }),
    )
    .await;
    assert_eq!(created_read["status"], "ok", "{created_read}");
    assert_eq!(created_read["data"]["data"], payload);
    bridge.shutdown().await.unwrap();
}

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
async fn fenced_library_operations_survive_with_authority() {
    recovery_kit_round_trip(&provider_binary("object-provider")).await;
}

/// The recovery key is missing. The Runtime refuses before it writes to the
/// helper pipe, and it does not create the key. A key that is already there
/// is narrowed to 0600 and its bytes stay the same.
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
fn recovery_key_missing_refuses_before_dispatch() {
    use std::os::unix::fs::PermissionsExt;
    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    crate::auth::store_test_principal_root_protection(&data, principal);
    let key = recovery_key_path(&data);
    let key_bytes = std::fs::read(&key).unwrap();
    std::fs::remove_file(&key).unwrap();
    let missing = crate::object_authority::ObjectAuthorityV1::build(&data, principal);
    let text = missing.unwrap_err().to_string();
    assert!(
        text.contains(crate::object_authority::RECOVERY_KEY_REFUSAL),
        "{text}"
    );
    assert!(!key.exists(), "the builder created the recovery key");
    std::fs::write(&key, &key_bytes).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let authority = crate::object_authority::ObjectAuthorityV1::build(&data, principal)
        .expect("object authority");
    assert_eq!(file_mode(&key), 0o600);
    assert_eq!(std::fs::read(&key).unwrap(), key_bytes);
    let shown = format!("{authority:?}");
    let key_hex = key_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(shown.contains("[redacted]"), "{shown}");
    assert!(!shown.contains(&key_hex), "{shown}");
}

/// Keyless operations do not read the recovery archive key. A missing key
/// still refuses an operation that opens an object envelope.
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
fn keyless_ops_attach_without_the_recovery_key() {
    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    crate::auth::store_test_principal_root_protection(&data, principal);
    let key = recovery_key_path(&data);
    std::fs::remove_file(&key).unwrap();
    for op in [
        "roots",
        "list_runtime_custody",
        "import_runtime_custody",
        "buy",
        "open_viewer",
        "read_viewer",
        "close_viewer",
    ] {
        let attached = crate::object_authority::ObjectAuthorityV1::attach(
            &data,
            &serde_json::json!({
                "op": op,
                "principal_id": principal,
            }),
        )
        .unwrap_or_else(|err| panic!("{op}: {err}"));
        let envelope = &attached[crate::object_authority::WIRE_FIELD];
        assert!(envelope["data_key"].is_null(), "{op} attached a data key");
        assert!(
            envelope["data_key_id"].is_null(),
            "{op} attached a data key id"
        );
        assert!(!key.exists(), "{op} created the recovery key");
    }
    let keyed = crate::object_authority::ObjectAuthorityV1::attach(
        &data,
        &serde_json::json!({
            "op": "list",
            "principal_id": principal,
        }),
    );
    let text = keyed.unwrap_err().to_string();
    assert!(
        text.contains(crate::object_authority::RECOVERY_KEY_REFUSAL),
        "{text}"
    );
    assert!(!key.exists(), "the keyed refusal created the recovery key");
}

/// Piece 2 still grants `ElastOS/System`. This row checks that grant by the
/// directory object start creates, and checks that a user-file write still
/// succeeds. It does not claim the helper is refused under Auth. Piece 3
/// removes the root and replaces this row with that refusal.
#[cfg(all(
    not(elastos_unsupported_os_check),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn object_helper_writes_a_user_file_while_elastos_system_is_granted_on_linux() {
    use base64::Engine;
    let (_hold, data) = helper_data_root();
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let auth = data.join("ElastOS/System/Auth");
    assert!(auth.join("auth-state.json").is_file());
    assert!(auth.join("recovery-archive.key").is_file());
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    assert!(
        data.join("ElastOS/System").is_dir(),
        "piece 2 still grants ElastOS/System, so the sign-in parent stays inside the object helper roots"
    );
    let uri = format!("{}/open.txt", protection.localhost_root);
    let payload = base64::engine::general_purpose::STANDARD.encode(b"open");
    let wrote = exchange_ok(
        &data,
        object.bridge(),
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": payload
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    object.bridge().shutdown().await.unwrap();
}

/// Piece 2 still grants `ElastOS/System`. This row checks that grant by the
/// directory object start creates, and checks that a user-file write still
/// succeeds. It does not claim the helper is refused under ElastOS. Piece 3
/// removes the root and replaces this row with that refusal.
#[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
#[tokio::test]
async fn object_helper_writes_a_user_file_while_elastos_system_is_granted_on_macos() {
    use base64::Engine;
    let (_hold, data) = helper_data_root();
    assert!(
        data.join("ElastOS").is_dir(),
        "ElastOS exists before the fence"
    );
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    assert!(
        data.join("ElastOS/System").is_dir(),
        "piece 2 still grants ElastOS/System, so the sign-in parent stays inside the object helper roots"
    );
    let uri = format!("{}/stat.txt", protection.localhost_root);
    let payload = base64::engine::general_purpose::STANDARD.encode(b"stat");
    let wrote = exchange_ok(
        &data,
        object.bridge(),
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": payload
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    object.bridge().shutdown().await.unwrap();
}

/// A split sign-in record is refused by the Runtime builder. The helper is
/// not asked, so it does not open the activation lock, and the two files
/// keep the bytes they had.
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
async fn runtime_builder_refuses_a_split_sign_in_record() {
    let (_hold, data) = helper_data_root();
    let ada = "person:local:ada";
    crate::auth::store_test_human_principal(&data, ada);
    let (auth_path, audit_path) = auth_record_paths(&data);
    let audit_ada = std::fs::read(&audit_path).unwrap();
    crate::auth::store_test_human_principal(&data, "person:local:bob");
    let audit_bob = std::fs::read(&audit_path).unwrap();
    if audit_ada != audit_bob {
        std::fs::write(&audit_path, &audit_ada).unwrap();
    } else {
        std::fs::remove_file(&audit_path).unwrap();
    }
    let auth_before = std::fs::read(&auth_path).unwrap();
    let audit_before = std::fs::read(&audit_path).ok();
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    let refused = crate::object_authority::ObjectAuthorityV1::build(&data, ada);
    let text = refused
        .as_ref()
        .err()
        .map(|err| err.to_string())
        .unwrap_or_default();
    assert!(
        refused.is_err(),
        "the builder accepted a split sign-in record"
    );
    assert!(
        text.contains("audit chain"),
        "the builder did not refuse with the audit sentence: {text}"
    );
    assert_eq!(std::fs::read(&auth_path).unwrap(), auth_before);
    assert_eq!(std::fs::read(&audit_path).ok(), audit_before);
    let auth_dir = auth_path.parent().unwrap();
    for entry in std::fs::read_dir(auth_dir).unwrap() {
        let name = entry.unwrap().file_name();
        let name = name.to_string_lossy();
        assert!(!name.contains(".tmp"), "the refused build left {name}");
    }
    object.bridge().shutdown().await.unwrap();
}

/// A capsule storage root under `Users/self/<dir>` is a start-walk root. The
/// helper holds no grant list; its depth bound covers every folder below a
/// person's root. mkdir, move, copy, and archive
/// extraction that would land 16 folders below it are refused by name, and
/// Home still starts.
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
async fn fenced_object_refuses_a_capsule_storage_root_at_depth_16() {
    use base64::Engine;
    let (_hold, data) = helper_data_root();
    let capsule = data.join("capsules/notes");
    std::fs::create_dir_all(&capsule).unwrap();
    std::fs::write(
        capsule.join("index.html"),
        "<!doctype html><title>Notes</title>",
    )
    .unwrap();
    std::fs::write(
        capsule.join("capsule.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule/v1",
            "name": "notes",
            "version": "0.1.0",
            "description": "Notes",
            "author": "elastos",
            "role": "app",
            "type": "data",
            "entrypoint": "index.html",
            "permissions": { "storage": ["localhost://Users/self/Notes/*"] }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        data.join("components.json"),
        serde_json::to_vec(&serde_json::json!({
            "external": {
                "notes": { "install_path": "capsules/notes", "platforms": {} }
            },
            "capsules": {},
            "profiles": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let grants = crate::api::capsule_inventory::read_active_storage_grants(&data)
        .unwrap_or_else(|err| panic!("grant read: {err}"));
    assert!(
        grants.iter().any(|grant| grant.contains("Notes")),
        "the fixture grant was not read: {grants:?}"
    );
    let principal = "person:local:ada";
    let protection = crate::auth::store_test_principal_root_protection(&data, principal);
    let root = protection.localhost_root;
    let notes = format!("{root}/Notes");
    let on_disk = |uri: &str| data.join(uri.trim_start_matches("localhost://"));
    let home_starts = |data: &std::path::Path| {
        crate::api::auth_gateway::verify_configured_principal_roots_ready(data)
            .unwrap_or_else(|err| panic!("Home did not start: {err:#}"));
    };
    let (_, did) = elastos_identity::load_or_create_did(&data).unwrap();
    let object = spawn_object(&provider_binary("object-provider"), &data, &did).await;
    let bridge = object.bridge();
    let kept = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": notes,
            "name": "kept"
        }),
    )
    .await;
    assert_eq!(kept["status"], "ok", "{kept}");
    home_starts(&data);

    let parent = format!(
        "{notes}/{}",
        (1..=15)
            .map(|n| format!("{n:02}"))
            .collect::<Vec<_>>()
            .join("/")
    );
    let deep = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "mkdir",
            "principal_id": principal,
            "parent_uri": parent,
            "name": "16"
        }),
    )
    .await;
    assert_eq!(deep["status"], "error", "{deep}");
    let deep_message = deep["message"].as_str().unwrap_or("");
    assert!(
        deep_message.contains("more than 16 folders deep") && deep_message.contains("Notes"),
        "{deep}"
    );
    assert!(
        !on_disk(&format!("{parent}/16")).exists(),
        "mkdir wrote the deep folder"
    );
    home_starts(&data);

    let hold = format!("{root}/hold");
    std::fs::create_dir_all(on_disk(&format!(
        "{hold}/{}",
        (1..=15)
            .map(|n| format!("{n:02}"))
            .collect::<Vec<_>>()
            .join("/")
    )))
    .unwrap();
    home_starts(&data);
    let moved = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "move",
            "principal_id": principal,
            "uri": hold,
            "target_parent_uri": notes
        }),
    )
    .await;
    assert_eq!(moved["status"], "error", "{moved}");
    let moved_message = moved["message"].as_str().unwrap_or("");
    assert!(
        moved_message.contains("more than 16 folders deep") && moved_message.contains("Notes"),
        "{moved}"
    );
    assert!(
        on_disk(&hold).is_dir(),
        "the refused move removed the source"
    );
    assert!(!on_disk(&format!("{notes}/hold")).exists());
    home_starts(&data);

    let copied = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "copy",
            "principal_id": principal,
            "uri": hold,
            "target_parent_uri": notes
        }),
    )
    .await;
    assert_eq!(copied["status"], "error", "{copied}");
    let copied_message = copied["message"].as_str().unwrap_or("");
    assert!(
        copied_message.contains("more than 16 folders deep") && copied_message.contains("Notes"),
        "{copied}"
    );
    assert!(on_disk(&hold).is_dir());
    assert!(!on_disk(&format!("{notes}/hold")).exists());
    home_starts(&data);

    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o700);
        header.set_size(0);
        let entry = (1..=15)
            .map(|n| format!("{n:02}"))
            .collect::<Vec<_>>()
            .join("/");
        header.set_path(format!("{entry}/")).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
        builder.finish().unwrap();
    }
    let tar_uri = format!("{notes}/deep.tar");
    let wrote = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": tar_uri,
            "data": base64::engine::general_purpose::STANDARD.encode(&archive)
        }),
    )
    .await;
    assert_eq!(wrote["status"], "ok", "{wrote}");
    let extracted = exchange_ok(
        &data,
        bridge,
        serde_json::json!({
            "op": "extract_archive",
            "principal_id": principal,
            "uri": tar_uri
        }),
    )
    .await;
    assert_eq!(extracted["status"], "error", "{extracted}");
    let extracted_message = extracted["message"].as_str().unwrap_or("");
    assert!(
        extracted_message.contains("more than 16 folders deep")
            && extracted_message.contains("Notes"),
        "{extracted}"
    );
    assert!(
        !on_disk(&format!("{notes}/deep")).exists(),
        "extraction created the folder"
    );
    home_starts(&data);
    bridge.shutdown().await.unwrap();
}
