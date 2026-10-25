use super::io_observer::{run_observed_child, LinkRace, Observation};
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
    if run_observed_child("tests::storage_boundary::wallet_operations_stay_under_root") {
        return;
    }
    let parent = tempfile::tempdir().unwrap();
    let base = parent.path().join("home");
    let cwd_before = entries(Path::new("."));

    let root_path = parent
        .path()
        .canonicalize()
        .unwrap()
        .join("home/ElastOS/SystemServices/Wallet");
    let bootstrap_observation = Observation::begin(&root_path, true);
    reset_accessed_paths();
    let mut provider = init_provider(&base);
    bootstrap_observation.finish();
    let operation_observation = Observation::begin(&root_path, false);
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

    operation_observation.finish();
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
    if run_observed_child("tests::storage_boundary::outside_root_access_is_detected") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    let mut provider = init_provider(&base);
    let root = wallet_root(&base);
    let outside = dir.path().join("outside-state.json");
    let sentinel = b"outside sentinel";
    fs::write(&outside, sentinel).unwrap();
    let before = entries(dir.path());
    let observation = Observation::begin(&root.canonicalize().unwrap(), false);
    // Exercise the real decoder and account mutation while the independent
    // observer is active. A direct read or transient write here is detectable.
    let created = invoke_wallet(
        &mut provider,
        "person:local:alice",
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: true,
        },
    );
    assert!(matches!(created, Response::Ok { .. }), "{created:?}");
    observation.finish();

    reset_accessed_paths();
    let read = load_store_if_present_under_root(provider.storage_root.as_ref().unwrap(), &outside);
    assert!(read
        .unwrap_err()
        .contains("must stay inside the configured wallet directory"));
    assert!(
        take_accessed_paths().is_empty(),
        "outside read reached the filesystem"
    );

    reset_accessed_paths();
    let write = save_store_under_root(
        provider.storage_root.as_ref().unwrap(),
        &outside,
        &WalletStore::default(),
    );
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
    assert!(save_store_under_root(
        provider.storage_root.as_ref().unwrap(),
        &escaping,
        &WalletStore::default()
    )
    .unwrap_err()
    .contains("must stay inside the configured wallet directory"));
    assert_eq!(fs::read(&outside).unwrap(), sentinel);
    assert_eq!(entries(dir.path()), before);
}

#[test]
fn bootstrap_access_is_bounded() {
    if run_observed_child("tests::storage_boundary::bootstrap_access_is_bounded") {
        return;
    }
    let parent = tempfile::tempdir().unwrap();
    let unrelated = parent.path().join("unrelated.txt");
    let unrelated_bytes = b"unrelated ancestor file";
    fs::write(&unrelated, unrelated_bytes).unwrap();
    let other = parent.path().join("other");
    fs::create_dir(&other).unwrap();
    let base = parent.path().join("home");

    let root_path = parent
        .path()
        .canonicalize()
        .unwrap()
        .join("home/ElastOS/SystemServices/Wallet");
    let observation = Observation::begin(&root_path, true);
    reset_accessed_paths();
    create_wallet_dir_durable(&wallet_root(&base)).unwrap();
    observation.finish();
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

#[cfg(unix)]
#[test]
fn wallet_storage_rejects_hard_linked_key() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    let wallet = wallet_root(&base);
    fs::create_dir_all(&wallet).unwrap();
    let outside = dir.path().join("outside-key.hex");
    let outside_bytes = b"not-hex\n";
    fs::write(&outside, outside_bytes).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
    fs::hard_link(&outside, wallet.join(WALLET_KEY_FILE)).unwrap();

    let mut provider = WalletProvider::new();
    match decode_and_handle_outer(
        &mut provider,
        json!({
            "op": "init",
            "config": { "base_path": base.display().to_string() }
        }),
    ) {
        Response::Error {
            ref code,
            ref message,
        } => {
            assert_eq!(code, "storage_error");
            assert_eq!(
                message,
                "wallet storage key must be owned by the wallet directory; it has 2 hard links"
            );
        }
        other => panic!("expected hard-linked key refusal, got {other:?}"),
    }
    assert!(provider.store_path.is_none());
    assert!(provider.storage_root.is_none());
    assert!(provider.storage_key.is_none());
    assert_eq!(fs::read(&outside).unwrap(), outside_bytes);
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o7777,
        0o644,
        "the outside inode mode changed"
    );
}

#[cfg(unix)]
#[test]
fn wallet_storage_rejects_hard_linked_store() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    let wallet = wallet_root(&base);
    fs::create_dir_all(&wallet).unwrap();
    let outside = dir.path().join("outside-state.json");
    let outside_bytes = serde_json::to_vec_pretty(&WalletStore::default()).unwrap();
    fs::write(&outside, &outside_bytes).unwrap();
    fs::hard_link(&outside, wallet.join("wallet-state.json")).unwrap();

    let mut provider = WalletProvider::new();
    match decode_and_handle_outer(
        &mut provider,
        json!({
            "op": "init",
            "config": { "base_path": base.display().to_string() }
        }),
    ) {
        Response::Error {
            ref code,
            ref message,
        } => {
            assert_eq!(code, "storage_error");
            assert_eq!(
                message,
                "wallet store must be owned by the wallet directory; it has 2 hard links"
            );
        }
        other => panic!("expected hard-linked store refusal, got {other:?}"),
    }
    assert!(provider.store_path.is_none());
    assert!(provider.storage_root.is_none());
    assert_eq!(fs::read(&outside).unwrap(), outside_bytes);
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

#[cfg(unix)]
fn assert_init_rejects_link_added_after_fstat(filename: &str, bytes: &[u8], reason: &str) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("home");
    let wallet = wallet_root(&base);
    fs::create_dir_all(&wallet).unwrap();
    let path = wallet.join(filename);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let outside = dir.path().join(filename);
    let linked_path = path.clone();
    let linked_outside = outside.clone();
    let race = LinkRace::begin(&path, move || {
        fs::hard_link(linked_path, linked_outside).unwrap();
    });
    let mut provider = WalletProvider::new();
    let response = decode_and_handle_outer(
        &mut provider,
        json!({ "op": "init", "config": { "base_path": base } }),
    );
    race.finish(1);
    match response {
        Response::Error { code, message } => {
            assert_eq!(code, "storage_error");
            assert_eq!(message, reason);
        }
        other => panic!("expected raced hard-link refusal, got {other:?}"),
    }
    assert!(provider.store_path.is_none());
    assert!(provider.storage_root.is_none());
    assert!(provider.storage_key.is_none());
    assert_eq!(fs::read(&outside).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o7777,
        0o644,
        "the outside inode mode changed"
    );
}

#[cfg(unix)]
#[test]
fn wallet_init_rejects_key_link_added_after_fstat_before_io() {
    if run_observed_child(
        "tests::storage_boundary::wallet_init_rejects_key_link_added_after_fstat_before_io",
    ) {
        return;
    }
    assert_init_rejects_link_added_after_fstat(
        WALLET_KEY_FILE,
        format!("{}\n", "ab".repeat(32)).as_bytes(),
        "wallet storage key must be owned by the wallet directory; it has 2 hard links",
    );
}

#[cfg(unix)]
#[test]
fn wallet_init_rejects_store_link_added_after_fstat_before_io() {
    if run_observed_child(
        "tests::storage_boundary::wallet_init_rejects_store_link_added_after_fstat_before_io",
    ) {
        return;
    }
    assert_init_rejects_link_added_after_fstat(
        "wallet-state.json",
        &serde_json::to_vec_pretty(&WalletStore::default()).unwrap(),
        "wallet store must be owned by the wallet directory; it has 2 hard links",
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

#[test]
fn init_creates_missing_base_path_chain() {
    let parent = tempfile::tempdir().unwrap();
    let base = parent.path().join("new/home");
    assert!(!base.parent().unwrap().exists());
    let provider = init_provider(&base);
    assert!(provider.storage_root.is_some());
    assert!(wallet_root(&base).is_dir());
    assert!(wallet_root(&base).join(WALLET_KEY_FILE).is_file());
}

#[cfg(unix)]
#[test]
fn wallet_operations_are_bound_to_initialized_directory() {
    use std::os::unix::fs::symlink;

    // Exercise every ancestor, including the configured base, and both reads
    // and writes. The original directory handle retains ownership after rename.
    for ancestor in [
        "",
        "ElastOS",
        "ElastOS/SystemServices",
        "ElastOS/SystemServices/Wallet",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let base = parent.path().join("home");
        let mut provider = init_provider(&base);
        let original_store = provider.store_path.clone().unwrap();
        let replaced = if ancestor.is_empty() {
            base.clone()
        } else {
            base.join(ancestor)
        };
        let held = parent.path().join("held");
        fs::rename(&replaced, &held).unwrap();
        let external = parent.path().join("external");
        let suffix = wallet_root(&base)
            .strip_prefix(&replaced)
            .unwrap()
            .to_path_buf();
        let external_wallet = external.join(&suffix);
        fs::create_dir_all(&external_wallet).unwrap();
        let external_store = external_wallet.join("wallet-state.json");
        let sentinel = b"outside wallet sentinel";
        fs::write(&external_store, sentinel).unwrap();
        symlink(&external, &replaced).unwrap();

        let created = invoke_wallet(
            &mut provider,
            "person:local:alice",
            "wallet",
            WalletProviderOperationV2::CreateManagedAccount {
                chain_namespace: "eip155:20".into(),
                label: None,
                create_new: true,
            },
        );
        assert!(
            matches!(created, Response::Ok { .. }),
            "{ancestor}: {created:?}"
        );
        assert_eq!(fs::read(&external_store).unwrap(), sentinel);
        let bound = load_store_if_present_under_root(
            provider.storage_root.as_ref().unwrap(),
            &original_store,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bound.accounts.len(), 1);
        assert!(held.join(&suffix).join("wallet-state.json").is_file());
        assert_eq!(
            entries(&external_wallet),
            BTreeSet::from([OsString::from("wallet-state.json")])
        );
        // Key reads use the same root, even after ancestor replacement.
        assert_eq!(
            load_or_create_storage_key(provider.storage_root.as_ref().unwrap()).unwrap(),
            provider.storage_key.unwrap()
        );
        assert_eq!(fs::read(&external_store).unwrap(), sentinel);
    }
}

#[test]
fn unchecked_storage_helpers_are_private() {
    let source = include_str!("../storage.rs");
    for name in [
        "load_store",
        "load_store_if_present",
        "save_store",
        "read_storage_key",
        "read_storage_key_if_present",
        "open_regular_file_if_present",
        "read_regular_file_if_present",
    ] {
        let signature = format!("fn {name}(");
        let line = source
            .lines()
            .find(|line| line.contains(&signature))
            .unwrap();
        assert!(
            line.starts_with(&signature),
            "unchecked helper is visible to callers: {line}"
        );
    }
    assert!(source.contains("fn bind<'a>"));
    assert!(!source.contains("pub(super) fn bind"));
    assert!(!source.contains("pub(super) struct Leaf"));
}

#[test]
fn raw_storage_helpers_are_inaccessible_to_provider() {
    // Compile the actual production modules with attempted calls from the
    // provider's scope. Reuse already-built dependencies; this does no build.
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut source = fs::read_to_string(source_dir.join("main.rs")).unwrap();
    source.push_str("\nfn unchecked_route_probe() { let _ = storage::save_store; let _ = storage::load_store_if_present; }\n");
    let fixture = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    collect_rust_files(&source_dir, &mut files);
    for file in files {
        let relative = file.strip_prefix(&source_dir).unwrap();
        if relative.starts_with("tests") {
            continue;
        }
        let copy = fixture.path().join(relative);
        fs::create_dir_all(copy.parent().unwrap()).unwrap();
        fs::copy(file, copy).unwrap();
    }
    let probe = fixture.path().join("main.rs");
    fs::write(&probe, source).unwrap();
    let executable = std::env::current_exe().unwrap();
    let dependencies = executable.parent().unwrap();
    let mut rustc = std::process::Command::new("rustc");
    rustc
        .args([
            "--edition=2021",
            "--emit=metadata",
            "--crate-name=wallet_storage_privacy",
        ])
        .arg(&probe)
        .arg("--out-dir")
        .arg(fixture.path())
        .arg("-L")
        .arg(format!("dependency={}", dependencies.display()))
        .env("CARGO_PKG_VERSION", env!("CARGO_PKG_VERSION"))
        .env("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"));
    for name in [
        "aes_gcm",
        "base64",
        "bitcoin",
        "elastos_auth",
        "elastos_protected_content_contracts",
        "elastos_wallet_contract",
        "hex",
        "k256",
        "rand",
        "rustix",
        "serde",
        "serde_json",
        "sha2",
        "sha3",
    ] {
        let mut candidates: Vec<_> = fs::read_dir(dependencies)
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .filter(|path| {
                let filename = path.file_name().unwrap().to_string_lossy();
                filename.starts_with(&format!("lib{name}-")) && filename.ends_with(".rlib")
            })
            .collect();
        if name == "sha3" {
            candidates.retain(|path| {
                let depfile = dependencies.join(format!(
                    "{}.d",
                    path.file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .trim_start_matches("lib")
                ));
                fs::read_to_string(depfile).unwrap().contains("/sha3-0.10.")
            });
        }
        // Cargo can leave artifacts from older runs. Select the newest complete
        // library for this dependency, as the current test build just emitted it.
        candidates.sort_by_key(|path| fs::metadata(path).unwrap().modified().unwrap());
        let library = candidates
            .last()
            .unwrap_or_else(|| panic!("missing compiled {name}"));
        rustc
            .arg("--extern")
            .arg(format!("{name}={}", library.display()));
    }
    let output = rustc.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "provider selected unchecked storage helpers"
    );
    for name in ["save_store", "load_store_if_present"] {
        assert!(
            stderr.contains(&format!("function `{name}` is private")),
            "{stderr}"
        );
    }
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("error["))
            .count(),
        2,
        "{stderr}"
    );
}
