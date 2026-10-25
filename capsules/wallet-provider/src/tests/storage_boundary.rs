use super::support::*;
use super::*;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

fn entries(path: &Path) -> BTreeSet<OsString> {
    fs::read_dir(path)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect()
}

fn wallet_root(base_path: &Path) -> PathBuf {
    wallet_dir_for_base(base_path)
}

fn lexically_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
        && !path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
}

fn assert_within_wallet_root(paths: &[PathBuf], root: &Path, base: &Path) {
    for path in paths {
        let inside_root = lexically_within(path, root);
        let bounded_ancestor = lexically_within(root, path) && lexically_within(path, base);
        assert!(
            inside_root || bounded_ancestor,
            "wallet storage accessed {} outside the configured wallet directory {}",
            path.display(),
            root.display()
        );
    }
}

#[test]
fn wallet_operations_stay_under_root() {
    let parent = tempfile::tempdir().unwrap();
    let base = parent.path().join("home");
    let cwd_before = entries(Path::new("."));

    reset_accessed_paths();
    let mut provider = init_provider(&base);
    let principal_id = "person:local:alice";

    let created = invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: Some("bounded".into()),
            create_new: true,
        },
    );
    assert!(matches!(created, Response::Ok { .. }), "{created:?}");

    let listed = invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: true,
        },
    );
    assert!(matches!(listed, Response::Ok { .. }), "{listed:?}");

    let root = wallet_root(&base);
    let accessed = take_accessed_paths();
    assert_within_wallet_root(&accessed, &root, &base);

    let store_path = provider.store_path.clone().unwrap();
    assert!(store_path.starts_with(&root));
    assert!(store_path.is_file());
    assert_eq!(entries(&base), BTreeSet::from([OsString::from("ElastOS")]));
    assert_eq!(
        entries(root.parent().unwrap()),
        BTreeSet::from([OsString::from("Wallet")]),
        "wallet operations wrote beside the configured wallet directory"
    );
    assert_eq!(
        entries(parent.path()),
        BTreeSet::from([OsString::from("home")]),
        "wallet operations left stray files beside the wallet root"
    );
    assert_eq!(
        entries(Path::new(".")),
        cwd_before,
        "wallet operations left stray files in the current directory"
    );
    let wallet_entries = entries(&root);
    assert!(wallet_entries.contains(&OsString::from("wallet-state.json")));
    assert!(wallet_entries.contains(&OsString::from("wallet-key.hex")));
    assert!(
        !wallet_entries
            .iter()
            .any(|name| name.to_string_lossy().ends_with(".tmp")),
        "wallet operations left staging files behind: {wallet_entries:?}"
    );
}

#[test]
fn outside_root_access_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    let _provider = init_provider(&base);
    let root = wallet_root(&base);
    let outside = dir.path().join("outside-state.json");
    let sentinel = b"outside sentinel";
    fs::write(&outside, sentinel).unwrap();
    let before = entries(dir.path());

    reset_accessed_paths();
    let read = load_store_if_present_under_root(&root, &outside);
    assert!(read
        .unwrap_err()
        .contains("must stay inside the configured wallet directory"));
    assert!(
        take_accessed_paths().is_empty(),
        "outside read reached the filesystem"
    );

    reset_accessed_paths();
    let write = save_store_under_root(&root, &outside, &WalletStore::default());
    assert!(write
        .unwrap_err()
        .contains("must stay inside the configured wallet directory"));
    assert!(
        take_accessed_paths().is_empty(),
        "outside write reached the filesystem"
    );
    assert_eq!(fs::read(&outside).unwrap(), sentinel);
    assert_eq!(entries(dir.path()), before);

    let escaping = root.join("..").join("outside-state.json");
    assert!(
        save_store_under_root(&root, &escaping, &WalletStore::default())
            .unwrap_err()
            .contains("must stay inside the configured wallet directory")
    );
    assert_eq!(fs::read(&outside).unwrap(), sentinel);
    assert_eq!(entries(dir.path()), before);
}

#[test]
fn bootstrap_access_is_bounded() {
    let parent = tempfile::tempdir().unwrap();
    let unrelated = parent.path().join("unrelated.txt");
    let unrelated_bytes = b"unrelated ancestor file";
    fs::write(&unrelated, unrelated_bytes).unwrap();
    let other = parent.path().join("other");
    fs::create_dir(&other).unwrap();
    let base = parent.path().join("home");

    reset_accessed_paths();
    create_wallet_dir_durable(&wallet_root(&base)).unwrap();
    let accessed = take_accessed_paths();
    for path in &accessed {
        assert!(
            lexically_within(path, &base),
            "bootstrap accessed {} above the configured base {}",
            path.display(),
            base.display()
        );
    }

    assert_eq!(fs::read(&unrelated).unwrap(), unrelated_bytes);
    assert_eq!(
        entries(parent.path()),
        BTreeSet::from([
            OsString::from("home"),
            OsString::from("other"),
            OsString::from("unrelated.txt"),
        ])
    );
}

#[cfg(unix)]
#[test]
fn wallet_bootstrap_rejects_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    fs::create_dir(&base).unwrap();
    let external = dir.path().join("external");
    fs::create_dir_all(external.join("SystemServices").join("Wallet")).unwrap();
    symlink(&external, base.join("ElastOS")).unwrap();

    let mut provider = WalletProvider::new();
    let init = decode_and_handle_outer(
        &mut provider,
        json!({
            "op": "init",
            "config": { "base_path": base.display().to_string() }
        }),
    );
    match init {
        Response::Error {
            ref code,
            ref message,
        } => {
            assert_eq!(code, "storage_error");
            assert!(
                message
                    .contains("wallet storage ancestor directory must be a non-symlink directory"),
                "{message}"
            );
        }
        other => panic!("expected symlinked ancestor refusal, got {other:?}"),
    }
    assert!(provider.store_path.is_none());
    assert!(provider.storage_root.is_none());
    assert!(provider.storage_key.is_none());
    assert_eq!(
        entries(&external.join("SystemServices").join("Wallet")),
        BTreeSet::new(),
        "wallet storage wrote through the symlinked ancestor"
    );
}

#[test]
fn init_rejects_invalid_base_path() {
    let missing_name = "wallet-relative-root-must-not-exist";
    assert!(!Path::new(missing_name).exists());

    for (config, reason) in [
        (
            json!({ "op": "init", "config": {} }),
            BASE_PATH_MISSING_REASON,
        ),
        (
            json!({ "op": "init", "config": { "base_path": "   " } }),
            BASE_PATH_EMPTY_REASON,
        ),
        (
            json!({ "op": "init", "config": { "base_path": missing_name } }),
            BASE_PATH_RELATIVE_REASON,
        ),
    ] {
        let mut provider = WalletProvider::new();
        match decode_and_handle_outer(&mut provider, config) {
            Response::Error { code, message } => {
                assert_eq!(code, "invalid_config");
                assert_eq!(message, reason);
            }
            other => panic!("expected base_path refusal {reason}, got {other:?}"),
        }
        assert!(provider.store_path.is_none());
        assert!(provider.storage_root.is_none());
        assert!(provider.storage_key.is_none());
    }
    assert!(
        !Path::new(missing_name).exists(),
        "relative base_path created a wallet outside the configured root"
    );
}

const FORBIDDEN_FILESYSTEM_TOKENS: &[&str] = &[
    "std::fs",
    "fs::",
    "OpenOptions",
    "File::",
    "read_to_string(",
    "std::os::unix::fs",
];

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

#[test]
fn filesystem_calls_stay_in_storage() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&source, &mut files);

    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&source).unwrap();
        if relative == Path::new("storage.rs")
            || relative == Path::new("tests/storage_boundary.rs")
            || relative.starts_with("tests")
        {
            continue;
        }
        let text = fs::read_to_string(&file).unwrap();
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if FORBIDDEN_FILESYSTEM_TOKENS
                .iter()
                .any(|token| code.contains(token))
            {
                offenders.push(format!(
                    "{}:{}: {}",
                    relative.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "filesystem access outside storage.rs: {offenders:#?}"
    );
}
