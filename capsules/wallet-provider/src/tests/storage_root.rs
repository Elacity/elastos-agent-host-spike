use super::support::*;
use super::*;
use std::fs;
use std::path::Path;

const PRINCIPAL_ID: &str = "person:local:alice";

fn assert_storage_refusal(response: Response, expected_reason: &str) {
    match response {
        Response::Error { code, message } => {
            assert_eq!(code, STORAGE_ERROR_CODE);
            assert_eq!(message, expected_reason);
        }
        other => panic!("expected storage refusal {expected_reason:?}, got {other:?}"),
    }
}

fn dir_entries(path: &Path) -> Vec<String> {
    let mut entries: Vec<String> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    entries
}

fn current_dir_entries() -> Vec<String> {
    dir_entries(&std::env::current_dir().unwrap())
}

fn init_with_config(provider: &mut WalletProvider, config: Value) -> Response {
    decode_and_handle_outer(provider, json!({ "op": "init", "config": config }))
}

fn link_operation(address: &str) -> WalletProviderOperationV2 {
    WalletProviderOperationV2::LinkVerifiedAccount {
        proof_binding_id: format!("proof:eip155:20:{address}"),
        chain_namespace: "eip155:20".into(),
        address: address.into(),
        proof_type: "siwe".into(),
        label: Some("ESC".into()),
    }
}

/// An absent root is refused before anything is written.
///
/// Falsifier: restore a current-directory or temp fallback when `base_path` is
/// missing; this Init then succeeds and the test fails.
#[test]
fn missing_storage_root_is_refused() {
    let before = current_dir_entries();
    let mut provider = WalletProvider::new();
    assert_storage_refusal(
        init_with_config(&mut provider, json!({})),
        STORAGE_PATH_NOT_SET,
    );
    assert!(
        provider.store_path.is_none() && provider.storage_key.is_none(),
        "a refused Init must leave no usable root"
    );
    assert_eq!(
        before,
        current_dir_entries(),
        "a missing root must not create files in the current directory"
    );
}

/// An empty or blank root has its own refusal reason.
///
/// Falsifier: accept an empty root by falling back to the current directory;
/// this Init then succeeds and the test fails.
#[test]
fn empty_storage_root_is_refused() {
    let before = current_dir_entries();
    for base_path in ["", "   "] {
        let mut provider = WalletProvider::new();
        assert_storage_refusal(
            init_with_config(&mut provider, json!({ "base_path": base_path })),
            STORAGE_PATH_EMPTY,
        );
        assert!(
            provider.store_path.is_none() && provider.storage_key.is_none(),
            "a refused Init must leave no usable root"
        );
    }
    assert_eq!(
        before,
        current_dir_entries(),
        "an empty root must not create files in the current directory"
    );
}

/// A relative root is refused with its own reason, before any write.
///
/// Falsifier: remove only the `is_absolute` check in `storage_root`; this Init
/// then accepts the relative root and the test fails.
#[test]
fn relative_storage_root_is_refused() {
    let relative = "wallet-provider-relative-root";
    let before = current_dir_entries();
    let mut provider = WalletProvider::new();
    assert_storage_refusal(
        init_with_config(&mut provider, json!({ "base_path": relative })),
        STORAGE_PATH_NOT_ABSOLUTE,
    );
    assert!(
        provider.store_path.is_none() && provider.storage_key.is_none(),
        "a refused Init must leave no usable root"
    );
    assert!(
        !Path::new(relative).exists(),
        "a relative root must not create its parent-side directory"
    );
    assert_eq!(
        before,
        current_dir_entries(),
        "a relative root must not create files in the current directory"
    );
}

#[test]
fn leading_whitespace_storage_root_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    fs::create_dir(&root).unwrap();
    let before_parent = dir_entries(parent.path());
    let before_root = dir_entries(&root);
    let before_cwd = current_dir_entries();

    for prefix in [" ", "\t", "\n", "\u{a0}"] {
        let mut provider = WalletProvider::new();
        let base_path = format!("{prefix}{}", root.display());
        assert_storage_refusal(
            init_with_config(&mut provider, json!({ "base_path": base_path })),
            "wallet-provider: storage path is not absolute",
        );
        assert!(
            provider.store_path.is_none() && provider.storage_key.is_none(),
            "a refused Init must leave no usable root"
        );
    }

    assert_eq!(dir_entries(&root), before_root);
    assert_eq!(dir_entries(parent.path()), before_parent);
    assert_eq!(current_dir_entries(), before_cwd);
}

#[test]
fn trailing_whitespace_storage_root_preserves_supplied_directory() {
    let parent = tempfile::tempdir().unwrap();
    let sibling = parent.path().join("root");
    let root = parent.path().join("root ");
    fs::create_dir(&sibling).unwrap();
    fs::create_dir(&root).unwrap();
    let before_sibling = dir_entries(&sibling);
    let before_parent = dir_entries(parent.path());
    let before_cwd = current_dir_entries();

    let mut provider = init_provider(&root);
    let response = invoke_wallet(
        &mut provider,
        PRINCIPAL_ID,
        "wallet-metamask",
        link_operation("0xabc"),
    );
    assert!(
        matches!(response, Response::Ok { .. }),
        "expected wallet write to succeed, got {response:?}"
    );

    let expected_store = root
        .join("ElastOS")
        .join("SystemServices")
        .join("Wallet")
        .join("wallet-state.json");
    assert!(
        expected_store.is_file(),
        "wallet state must persist under the supplied root with trailing whitespace"
    );
    assert_eq!(
        provider.store_path.as_deref(),
        Some(expected_store.as_path())
    );
    assert_eq!(
        dir_entries(&sibling),
        before_sibling,
        "the sibling with the trimmed name must stay unchanged"
    );
    assert_eq!(dir_entries(parent.path()), before_parent);
    assert_eq!(current_dir_entries(), before_cwd);

    let mut reloaded = init_provider(&root);
    match invoke_wallet(
        &mut reloaded,
        PRINCIPAL_ID,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let accounts = data["accounts"].as_array().unwrap();
            assert_eq!(accounts.len(), 1);
            assert_eq!(accounts[0]["account_id"], "wallet:eip155:20:0xabc");
        }
        other => panic!("expected the persisted account from the supplied root, got {other:?}"),
    }
    assert_eq!(dir_entries(&sibling), before_sibling);
}

/// A refused re-init revokes the previous root and keeps its files intact.
///
/// Falsifier: validate the new root before the state reset, so a second Init
/// without `base_path` keeps the first root; the following write then succeeds
/// and the test fails.
#[test]
fn wallet_reinit_refusal_revokes_previous_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let response = invoke_wallet(
        &mut provider,
        PRINCIPAL_ID,
        "wallet-metamask",
        link_operation("0xabc"),
    );
    assert!(
        matches!(response, Response::Ok { .. }),
        "expected first write to succeed, got {response:?}"
    );

    let store_path = dir
        .path()
        .join("ElastOS")
        .join("SystemServices")
        .join("Wallet")
        .join("wallet-state.json");
    let persisted = fs::read(&store_path).unwrap();

    let before = current_dir_entries();
    assert_storage_refusal(
        init_with_config(&mut provider, json!({})),
        STORAGE_PATH_NOT_SET,
    );
    assert!(
        provider.store_path.is_none() && provider.storage_key.is_none(),
        "a refused re-init must revoke the previous root"
    );

    let response = invoke_wallet(
        &mut provider,
        PRINCIPAL_ID,
        "wallet",
        link_operation("0xdef"),
    );
    match response {
        Response::Error { code, message } => {
            assert_eq!(code, "not_initialized");
            assert_eq!(message, "wallet-provider is not initialized");
        }
        other => panic!("expected a refused write after re-init refusal, got {other:?}"),
    }

    assert_eq!(
        fs::read(&store_path).unwrap(),
        persisted,
        "a refused re-init must not touch the previous root's files"
    );
    assert_eq!(
        before,
        current_dir_entries(),
        "a refused re-init must not create files in the current directory"
    );
}

/// A real wallet write persists only under the root Init was given.
///
/// Falsifier: move the production store destination (for example
/// `<root>/ElastOS/SystemServices/Wallet` to a sibling or the process working
/// directory); the store-path assertion and the parent snapshot then fail.
#[test]
fn wallet_operations_stay_under_root() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    fs::create_dir(&root).unwrap();
    let before_parent = dir_entries(parent.path());
    let before_cwd = current_dir_entries();

    let mut provider = WalletProvider::new();
    match init_with_config(
        &mut provider,
        json!({ "base_path": root.display().to_string() }),
    ) {
        Response::Ok { data: Some(data) } => assert_eq!(data["storage_configured"], true),
        other => panic!("expected init ok, got {other:?}"),
    }

    let expected_store = root
        .join("ElastOS")
        .join("SystemServices")
        .join("Wallet")
        .join("wallet-state.json");
    assert_eq!(
        provider.store_path.as_deref(),
        Some(expected_store.as_path()),
        "the production store destination must stay under the given root"
    );

    let response = invoke_wallet(
        &mut provider,
        PRINCIPAL_ID,
        "wallet-metamask",
        link_operation("0xabc"),
    );
    assert!(
        matches!(response, Response::Ok { .. }),
        "expected wallet write to succeed, got {response:?}"
    );

    assert!(
        expected_store.is_file(),
        "wallet state must persist under the given root"
    );
    assert_eq!(
        dir_entries(parent.path()),
        before_parent,
        "a wallet write must not create paths beside the root"
    );
    assert_eq!(
        current_dir_entries(),
        before_cwd,
        "a wallet write must not create paths in the current directory"
    );

    let mut reloaded = init_provider(&root);
    match invoke_wallet(
        &mut reloaded,
        PRINCIPAL_ID,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let accounts = data["accounts"].as_array().unwrap();
            assert_eq!(accounts.len(), 1);
            assert_eq!(accounts[0]["account_id"], "wallet:eip155:20:0xabc");
        }
        other => panic!("expected the persisted account from the root, got {other:?}"),
    }
}
