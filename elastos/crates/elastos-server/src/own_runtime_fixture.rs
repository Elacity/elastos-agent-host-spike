//! A signed Home whose runtime file no longer matches its release.
//! Binary-crate route tests use this. The library fixture is `pub(crate)` and
//! is compiled only into library tests.

use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub(crate) struct SubstitutedRuntimeHome {
    _root: tempfile::TempDir,
    pub(crate) data: PathBuf,
}

pub(crate) fn substituted_runtime_home() -> SubstitutedRuntimeHome {
    let root = tempfile::tempdir().unwrap();
    let data = std::fs::canonicalize(root.path()).unwrap();
    let binary = data.join("runtime");
    let original = b"installed signed runtime";
    std::fs::write(&binary, original).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    let components =
        br#"{"schema":"elastos.components/v1","external":{},"capsules":{},"profiles":{}}"#;
    std::fs::write(data.join("components.json"), components).unwrap();
    let platform = elastos_server::update::detect_release_platform();
    let release = signed(
        &serde_json::json!({
            "schema": "elastos.release/v1",
            "version": "0.7.0",
            "channel": "stable",
            "platforms": { platform: {
                "binary": descriptor(original),
                "components": descriptor(components),
            }},
        }),
        "elastos.release.v1",
    );
    let head = signed(
        &serde_json::json!({
            "schema": "elastos.release.head/v1",
            "version": "0.7.0",
            "channel": "stable",
            "latest_release_cid": raw_cid(&release),
            "release_sha256": hex::encode(sha2::Sha256::digest(&release)),
        }),
        "elastos.release.head.v1",
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let source: elastos_server::sources::TrustedSource =
        serde_json::from_value(serde_json::json!({
            "name": "fixture",
            "publisher_dids": [elastos_server::crypto::encode_signing_key_did(&key)],
            "channel": "stable",
            "installed_version": "0.7.0",
            "install_path": binary,
            "head_cid": raw_cid(&head),
        }))
        .unwrap();
    let head_path = elastos_common::localhost::publisher_release_head_path(&data);
    std::fs::create_dir_all(head_path.parent().unwrap()).unwrap();
    std::fs::write(&head_path, &head).unwrap();
    std::fs::write(
        elastos_common::localhost::publisher_release_manifest_path(&data),
        &release,
    )
    .unwrap();
    std::fs::write(
        data.join("sources.json"),
        serde_json::to_vec(&elastos_server::sources::TrustedSourcesConfig {
            schema: "elastos.trusted-sources/v1".into(),
            default_source: source.name.clone(),
            sources: vec![source],
        })
        .unwrap(),
    )
    .unwrap();
    // `dev_mode = true` must not admit the replaced bytes.
    std::fs::write(&binary, b"substituted runtime").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(data.join("config.toml"), "dev_mode = true\n").unwrap();
    SubstitutedRuntimeHome { _root: root, data }
}

fn signed(payload: &serde_json::Value, domain: &str) -> Vec<u8> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let (signature, signer_did) = elastos_server::crypto::domain_separated_sign(
        &key,
        domain,
        &serde_json::to_vec(payload).unwrap(),
    );
    serde_json::to_vec(&serde_json::json!({
        "payload": payload,
        "signature": signature,
        "signer_did": signer_did,
    }))
    .unwrap()
}

fn raw_cid(bytes: &[u8]) -> String {
    cid::Cid::new_v1(
        0x55,
        cid::multihash::Multihash::<64>::wrap(0x12, &sha2::Sha256::digest(bytes)).unwrap(),
    )
    .to_string()
}

fn descriptor(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "cid": raw_cid(bytes),
        "sha256": hex::encode(sha2::Sha256::digest(bytes)),
        "size": bytes.len(),
    })
}
