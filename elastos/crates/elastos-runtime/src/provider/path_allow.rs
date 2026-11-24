//! File allow-list for localhost and object.
//!
//! A single `STORAGE_ROOT` of the data directory would include
//! `identity/device.key`. Each helper gets its own child directories instead.
//! Each of those directories must already exist, be owned by the current user,
//! and must not be a symlink. `spawn_path_allow` starts localhost, object,
//! and chain. Chain's resolver files are read-only and are not a storage
//! root. The single-root `spawn_confined` does not start these helpers.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One rendered helper confinement. `landlock` is the path-beneath plan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HelperConfinement {
    pub seatbelt: String,
    pub landlock_abi: u32,
    pub landlock_handled: u64,
    pub landlock: Vec<HelperLandlockRule>,
    /// Data directory and its ancestors. Seatbelt `file-read-metadata` literals
    /// only. They are not Landlock rules: a path-beneath rule here would include
    /// `identity/device.key`.
    pub metadata: Vec<PathBuf>,
}

/// One Landlock path rule. `mask` is the ABI-5 access bits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HelperLandlockRule {
    pub name: &'static str,
    pub path: PathBuf,
    pub mask: u64,
}

#[derive(Clone, Copy)]
enum HelperId {
    Localhost,
    Object,
    Chain,
}

/// Object path builders name these file-backed roots:
/// `AUTH_STATE_ROOT` (`ElastOS/System/Auth`), principal roots
/// `localhost://Users/` and `localhost://UsersAI/`, and the published index
/// under `ElastOS`.
const OBJECT_ROOTS: &[&str] = &["ElastOS", "Users", "UsersAI"];

/// `node_lifecycle_state_path` joins this directory under the data directory.
const CHAIN_ROOTS: &[&str] = &["chain-provider"];

fn file_roots(provider: HelperId) -> &'static [&'static str] {
    match provider {
        HelperId::Localhost => elastos_common::localhost::FILE_BACKED_ROOTS,
        HelperId::Object => OBJECT_ROOTS,
        HelperId::Chain => CHAIN_ROOTS,
    }
}

fn runtime_provider(provider: HelperId) -> super::rights_table::RuntimeProviderId {
    match provider {
        HelperId::Localhost => super::rights_table::RuntimeProviderId::Localhost,
        HelperId::Object => super::rights_table::RuntimeProviderId::Object,
        HelperId::Chain => super::rights_table::RuntimeProviderId::Chain,
    }
}

/// The data directory and every ancestor except `/`, for both the path the
/// caller passed and its canonical path. `/` already has `file-read*`.
fn metadata_literals(data_dir: &Path) -> Result<Vec<PathBuf>, String> {
    if !data_dir.is_absolute() {
        return Err(
            "provider start is refused: the data directory path is not absolute".to_string(),
        );
    }
    let canonical = std::fs::canonicalize(data_dir).map_err(|_| {
        "provider start is refused: the data directory could not be resolved".to_string()
    })?;
    let mut paths = Vec::new();
    for start in [data_dir, canonical.as_path()] {
        let mut current = Some(start);
        while let Some(path) = current {
            if path == Path::new("/") {
                break;
            }
            if !paths.iter().any(|seen| seen == path) {
                paths.push(path.to_path_buf());
            }
            current = path.parent();
        }
    }
    if paths.is_empty() {
        return Err(
            "provider start is refused: the data directory has no metadata path".to_string(),
        );
    }
    Ok(paths)
}

fn helper_id(component_key: &str) -> Result<HelperId, String> {
    match component_key {
        "localhost-provider" => Ok(HelperId::Localhost),
        "object-provider" => Ok(HelperId::Object),
        "chain-provider" => Ok(HelperId::Chain),
        _ => Err(format!(
            "provider start is refused: component key \"{component_key}\" has no path allow-list"
        )),
    }
}

fn valid_root_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !matches!(
            name,
            "STORAGE_ROOT"
                | "STORAGE_PARENT"
                | "PROVIDER_EXECUTABLE"
                | "LANDLOCK_LOADER_PATHS"
                | "identity"
                | "device.key"
        )
}

/// `granted` is a path-beneath rule. `/` and any ancestor of `identity/` or
/// `identity/device.key` reaches the device key.
fn reaches_device_key(data_dir: &Path, granted: &Path) -> bool {
    if !granted.is_absolute() || granted == Path::new("/") {
        return true;
    }
    let identity = data_dir.join("identity");
    let key = identity.join("device.key");
    identity.starts_with(granted) || key.starts_with(granted)
}

/// The effective user is the current user. The single-root storage check uses
/// the same id.
fn current_user() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

/// `path` is one allow-list root. It must be a real directory this user owns,
/// and its resolved path must stay a child of `data_dir` that does not reach
/// `identity/` or `identity/device.key`.
fn require_real_root(data_dir: &Path, name: &str, path: &Path) -> Result<(u64, u64), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| format!("provider start is refused: {name} is not an existing directory"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("provider start is refused: {name} is a symlink"));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "provider start is refused: {name} is not a directory"
        ));
    }
    if metadata.uid() != current_user() {
        return Err(format!(
            "provider start is refused: {name} is not owned by the current user"
        ));
    }
    let resolved = std::fs::canonicalize(path)
        .map_err(|_| format!("provider start is refused: {name} could not be resolved"))?;
    let data_resolved = std::fs::canonicalize(data_dir).map_err(|_| {
        "provider start is refused: the data directory could not be resolved".to_string()
    })?;
    if reaches_device_key(&data_resolved, &resolved) {
        return Err(format!(
            "provider start is refused: {name} reaches identity/device.key"
        ));
    }
    if resolved.parent() != Some(data_resolved.as_path()) {
        return Err(format!(
            "provider start is refused: {name} resolves outside the data directory"
        ));
    }
    let (dev, ino) = (metadata.dev(), metadata.ino());
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("provider start is refused: {name} contains NUL"))?;
    // The same open the installer repeats at launch. Dropping the descriptor
    // closes it; render only needed the identity check.
    let _held = super::root_pin::open_pinned_directory(
        &c_path,
        super::root_pin::DIRECTORY_OPEN_FLAGS,
        dev,
        ino,
    )
    .map_err(|errno| {
        format!(
            "provider start is refused: {name} is not the directory that was checked: errno {errno}"
        )
    })?;
    Ok((dev, ino))
}

fn resolve_roots(
    provider: HelperId,
    data_dir: &Path,
) -> Result<Vec<super::landlock_plan::AllowRoot>, String> {
    if !data_dir.is_absolute() {
        return Err(
            "provider start is refused: the data directory path is not absolute".to_string(),
        );
    }
    let names = file_roots(provider);
    if names.is_empty() {
        return Err("provider start is refused: the path allow-list has no file roots".to_string());
    }
    let mut resolved: Vec<super::landlock_plan::AllowRoot> = Vec::with_capacity(names.len());
    for name in names {
        if !valid_root_name(name) {
            return Err(format!(
                "provider start is refused: {name} cannot be a path allow-list root"
            ));
        }
        if matches!(provider, HelperId::Localhost | HelperId::Object)
            && !elastos_common::localhost::FILE_BACKED_ROOTS.contains(name)
        {
            return Err(format!(
                "provider start is refused: {name} is outside the file-backed roots"
            ));
        }
        let path = data_dir.join(name);
        if path.parent() != Some(data_dir) || reaches_device_key(data_dir, &path) {
            return Err(format!(
                "provider start is refused: {name} reaches identity/device.key"
            ));
        }
        if resolved.iter().any(|seen| seen.name == *name) {
            return Err(format!("provider start is refused: {name} is listed twice"));
        }
        let (dev, ino) = require_real_root(data_dir, name, &path)?;
        resolved.push(super::landlock_plan::AllowRoot {
            name,
            path,
            dev,
            ino,
        });
    }
    Ok(resolved)
}

fn read_only_files_are_the_resolver_list(
    provider: HelperId,
    data_dir: &Path,
    rules: &[HelperLandlockRule],
) -> Result<(), String> {
    const FILES: &[&str] = &["/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"];
    let files: Vec<_> = rules
        .iter()
        .filter(|rule| rule.name == "READ_ONLY_FILE")
        .collect();
    if !matches!(provider, HelperId::Chain) {
        if files.is_empty() {
            return Ok(());
        }
        return Err(
            "provider start is refused: a read-only resolver file is not a chain grant".into(),
        );
    }
    for rule in files {
        let text = rule.path.to_str().unwrap_or("");
        if !FILES.contains(&text) || rule.mask != 4 || rule.path.starts_with(data_dir) {
            return Err(format!(
                "provider start is refused: {} is not a chain resolver file",
                rule.path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn render(
    component_key: &str,
    data_dir: &Path,
    executable: &Path,
    landlock_abi: u32,
) -> Result<HelperConfinement, String> {
    Ok(render_with_plan(component_key, data_dir, executable, landlock_abi)?.0)
}

pub(super) fn render_with_plan(
    component_key: &str,
    data_dir: &Path,
    executable: &Path,
    landlock_abi: u32,
) -> Result<(HelperConfinement, super::landlock_plan::PathAllowPlan), String> {
    let provider = helper_id(component_key)?;
    let roots = resolve_roots(provider, data_dir)?;
    if reaches_device_key(data_dir, executable) {
        return Err(
            "provider start is refused: the executable path reaches identity/device.key"
                .to_string(),
        );
    }
    let names: Vec<&str> = roots.iter().map(|root| root.name).collect();
    let chain = matches!(provider, HelperId::Chain);
    // Chain's measured profile has no ancestor metadata. The data directory
    // stays out of the Seatbelt text, so identity/device.key stays unreadable.
    let metadata = if chain {
        Vec::new()
    } else {
        metadata_literals(data_dir)?
    };
    let seatbelt = super::macos_profile::render_path_allow_profile(&names, metadata.len(), chain)?;
    if seatbelt.contains("STORAGE_ROOT")
        || seatbelt.contains("STORAGE_PARENT")
        || seatbelt.contains("identity")
    {
        return Err(
            "provider start is refused: the Seatbelt profile names a forbidden path".to_string(),
        );
    }
    let plan = super::landlock_plan::build_path_allow_plan(
        runtime_provider(provider),
        &roots,
        executable,
        landlock_abi,
    )?;
    if plan.root_dev.len() != roots.len() || plan.root_ino.len() != roots.len() {
        return Err(
            "provider start is refused: the Landlock plan has no identity for a root".to_string(),
        );
    }
    for (index, root) in roots.iter().enumerate() {
        if plan.root_dev[index] != root.dev || plan.root_ino[index] != root.ino {
            return Err(
                "provider start is refused: the Landlock plan lost a root identity".to_string(),
            );
        }
    }
    let landlock = plan
        .rules
        .iter()
        .map(|rule| HelperLandlockRule {
            name: rule.0,
            path: rule.1.clone(),
            mask: rule.2,
        })
        .collect::<Vec<_>>();
    if landlock
        .iter()
        .any(|rule| reaches_device_key(data_dir, &rule.path))
    {
        return Err(
            "provider start is refused: the Landlock plan reaches identity/device.key".to_string(),
        );
    }
    read_only_files_are_the_resolver_list(provider, data_dir, &landlock)?;
    Ok((
        HelperConfinement {
            seatbelt,
            landlock_abi: plan.abi,
            landlock_handled: plan.handled,
            landlock,
            metadata,
        },
        plan,
    ))
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use std::path::Path;

    const EXE: &str = "/opt/elastos/helper-provider";

    fn real_data_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("data directory");
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            std::fs::create_dir(tmp.path().join(name))
                .unwrap_or_else(|err| panic!("{name}: {err}"));
        }
        std::fs::create_dir(tmp.path().join("chain-provider")).expect("chain-provider");
        tmp
    }
    const WALLET_PROFILE: &str = "\
(version 1)
(deny default)
(deny network*)
(allow process-exec (literal (param \"PROVIDER_EXECUTABLE\")))
(allow file-read* (literal \"/\"))
(allow sysctl-read)
(allow file-read* (literal (param \"STORAGE_PARENT\")))
(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))
";

    fn reaches(granted: &Path, secret: &Path) -> bool {
        !granted.is_absolute() || granted == Path::new("/") || secret.starts_with(granted)
    }

    fn quoted<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
        let rest = line.split_once(marker)?.1;
        Some(&rest[..rest.find('"')?])
    }

    #[test]
    fn localhost_object_and_chain_profiles_omit_device_key() {
        let held = real_data_dir();
        let data_dir = held.path();
        let executable = Path::new(EXE);
        let identity = data_dir.join("identity");
        let key = identity.join("device.key");
        let store = include_str!("../../../elastos-identity/src/store.rs");
        assert!(
            store.contains("data_dir.join(\"identity\").join(\"device.key\")"),
            "device.key path moved"
        );
        let auth = include_str!("../../../elastos-server/src/auth.rs");
        assert!(auth.contains("const AUTH_STATE_ROOT: &str = \"ElastOS/System/Auth\""));
        assert!(auth.contains("localhost://Users/"));
        assert!(auth.contains("localhost://UsersAI/"));
        let lifecycle = include_str!("../../../../../capsules/chain-provider/src/lifecycle.rs");
        assert!(lifecycle.contains(".join(\"chain-provider\")"));
        for name in ["ElastOS", "Users", "UsersAI"] {
            assert!(
                elastos_common::localhost::FILE_BACKED_ROOTS.contains(&name),
                "{name} left the file-backed roots"
            );
        }

        let cases: &[(&str, &[&str])] = &[
            (
                "localhost-provider",
                elastos_common::localhost::FILE_BACKED_ROOTS,
            ),
            ("object-provider", &["ElastOS", "Users", "UsersAI"]),
            ("chain-provider", &["chain-provider"]),
        ];
        let did = super::super::landlock_plan::build(
            super::super::rights_table::RuntimeProviderId::Did,
            &super::super::rights::admit_committed(
                super::super::rights_table::RuntimeProviderId::Did,
            ),
            &super::super::landlock_plan::Bindings {
                storage_root: "/provider/Did".into(),
                provider_executable: "/bin/Did".into(),
                storage_dev: 1,
                storage_ino: 1,
            },
            5,
        )
        .unwrap();
        let storage_mask = did
            .rules
            .iter()
            .find(|rule| rule.0 == "STORAGE_ROOT")
            .unwrap()
            .2;
        let binary_mask = did
            .rules
            .iter()
            .find(|rule| rule.0 == "PROVIDER_EXECUTABLE")
            .unwrap()
            .2;
        let did_loaders: Vec<_> = did
            .rules
            .iter()
            .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
            .map(|rule| rule.1.clone())
            .collect();

        for (component_key, expected) in cases {
            assert!(
                super::super::rights_table::RuntimeProviderId::from_component_key(component_key)
                    .is_none(),
                "{component_key} stays outside single-root spawn_confined"
            );
            let rendered = super::super::os_entry::render_helper_confinement(
                component_key,
                data_dir,
                executable,
                5,
            )
            .unwrap_or_else(|err| panic!("{component_key}: {err}"));
            let chain = *component_key == "chain-provider";
            assert!(rendered
                .seatbelt
                .starts_with("(version 1)\n(deny default)\n(deny network*)\n"));
            if chain {
                assert!(rendered.seatbelt.contains(
                    "(allow network-outbound (remote unix-socket (literal \"/private/var/run/mDNSResponder\")) (remote ip))"
                ));
                assert!(rendered.seatbelt.contains(
                    "(allow file-read* (literal \"/var\") (literal \"/var/run/resolv.conf\"))"
                ));
                assert!(!rendered.seatbelt.contains("mach-lookup"));
                assert!(!rendered.seatbelt.contains("/etc"));
                assert!(
                    rendered.metadata.is_empty(),
                    "chain metadata would name the data directory"
                );
            } else {
                assert!(!rendered.seatbelt.contains("(allow network"));
                assert!(
                    !rendered.metadata.is_empty(),
                    "{component_key} metadata literals"
                );
                assert!(rendered.metadata.iter().any(|path| path == data_dir));
            }
            assert!(rendered
                .metadata
                .iter()
                .all(|path| { path != Path::new("/") && path != &key && path != &identity }));
            assert!(!rendered
                .landlock
                .iter()
                .any(|rule| rendered.metadata.iter().any(|path| path == &rule.path)));
            assert!(!rendered
                .seatbelt
                .contains(data_dir.to_str().expect("data directory path")));
            assert!(!rendered.seatbelt.contains("identity"));
            assert!(!rendered.seatbelt.contains("STORAGE_ROOT"));
            assert!(!rendered.seatbelt.contains("STORAGE_PARENT"));
            assert_eq!(rendered.landlock_abi, did.abi);
            assert_eq!(rendered.landlock_handled, did.handled);

            let mut subpaths = Vec::new();
            let mut literals = Vec::new();
            for line in rendered.seatbelt.lines() {
                if let Some(name) = quoted(line, "(subpath (param \"") {
                    subpaths.push(name);
                } else if let Some(name) = quoted(line, "(literal (param \"") {
                    literals.push(name);
                } else if quoted(line, "(subpath \"").is_some() || line.contains("(subpath ") {
                    panic!("{component_key} subpath is not a named root: {line}");
                } else if let Some(path) = quoted(line, "(literal \"") {
                    let allowed = if chain {
                        path == "/"
                            || path == "/var"
                            || path == "/var/run/resolv.conf"
                            || path == "/private/var/run/mDNSResponder"
                    } else {
                        path == "/"
                    };
                    assert!(allowed, "{component_key} literal {path}");
                }
            }
            assert_eq!(subpaths, *expected, "{component_key} seatbelt roots");
            assert_eq!(literals.first().copied(), Some("PROVIDER_EXECUTABLE"));
            if chain {
                assert_eq!(literals, ["PROVIDER_EXECUTABLE"]);
            } else {
                assert!(
                    literals.len() > 1
                        && literals
                            .iter()
                            .skip(1)
                            .all(|name| name.starts_with("META_")),
                    "{component_key} literals {literals:?}"
                );
            }
            for line in rendered.seatbelt.lines() {
                if line.contains("META_") {
                    assert!(line.contains("file-read-metadata"), "{line}");
                    assert!(!line.contains("file-read-data"), "{line}");
                    assert!(!line.contains("subpath"), "{line}");
                }
            }

            let (roots, rest): (Vec<_>, Vec<_>) = rendered.landlock.iter().partition(|rule| {
                rule.name != "PROVIDER_EXECUTABLE"
                    && rule.name != "LANDLOCK_LOADER_PATHS"
                    && rule.name != "READ_ONLY_FILE"
            });
            let resolver: Vec<_> = rendered
                .landlock
                .iter()
                .filter(|rule| rule.name == "READ_ONLY_FILE")
                .collect();
            if chain {
                const ALLOWED: &[&str] = &["/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"];
                for rule in &resolver {
                    let path = rule.path.to_str().unwrap();
                    assert!(ALLOWED.contains(&path), "{path}");
                    assert_eq!(rule.mask, 4, "{path}");
                    assert!(!rule.path.starts_with(data_dir));
                }
            } else {
                assert!(resolver.is_empty(), "{component_key} gained resolver files");
            }
            assert_eq!(roots.len(), expected.len(), "{component_key} root count");
            for (rule, name) in roots.iter().zip(expected.iter()) {
                let path = data_dir.join(name);
                assert_eq!(rule.name, *name, "{component_key}");
                assert_eq!(rule.path, path, "{component_key}");
                assert_eq!(
                    rule.path.parent(),
                    Some(data_dir),
                    "allow list grew to the whole data directory: {:?}",
                    rule.path
                );
                assert!(
                    !reaches(&rule.path, &key) && !reaches(&rule.path, &identity),
                    "{component_key} reaches the device key through {}",
                    rule.path.display()
                );
                assert_eq!(rule.mask, storage_mask, "{component_key} mask");
            }
            let executable_rules: Vec<_> = rest
                .iter()
                .filter(|rule| rule.name == "PROVIDER_EXECUTABLE")
                .collect();
            assert_eq!(executable_rules.len(), 1, "{component_key} executable");
            assert_eq!(executable_rules[0].path, executable);
            assert_eq!(executable_rules[0].mask, binary_mask);
            let loaders: Vec<_> = rest
                .iter()
                .filter(|rule| rule.name == "LANDLOCK_LOADER_PATHS")
                .map(|rule| rule.path.clone())
                .collect();
            assert_eq!(loaders, did_loaders, "{component_key} loaders");
            for rule in &rendered.landlock {
                assert!(
                    !reaches(&rule.path, &key) && !reaches(&rule.path, &identity),
                    "{component_key} Landlock rule {} reaches the device key",
                    rule.path.display()
                );
                assert_ne!(
                    rule.path, data_dir,
                    "allow list grew to the whole data directory"
                );
            }
        }

        let wallet = super::super::macos_profile::render_macos_profile(
            super::super::rights_table::RuntimeProviderId::Wallet,
            &super::super::rights::admit_committed(
                super::super::rights_table::RuntimeProviderId::Wallet,
            ),
        );
        assert_eq!(
            wallet, WALLET_PROFILE,
            "wallet profile changed; single-root profiles stay byte-identical"
        );
        let oracle = include_str!("../../../../../capsules/wallet-provider/confine.sb");
        let oracle_rules: Vec<_> = oracle
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('('))
            .collect();
        let wallet_rules: Vec<_> = wallet
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('('))
            .collect();
        assert_eq!(wallet_rules, oracle_rules, "wallet profile left its oracle");

        let refused = super::super::os_entry::render_helper_confinement(
            "wallet-provider",
            data_dir,
            executable,
            5,
        );
        assert!(refused.is_err(), "wallet stays on its single-root profile");
    }

    #[test]
    fn a_root_that_is_a_symlink_to_data_dir_or_to_data_dir_identity_is_refused_at_render() {
        let providers: &[(&str, &str)] = &[
            ("localhost-provider", "ElastOS"),
            ("object-provider", "Users"),
            ("chain-provider", "chain-provider"),
        ];
        for (component, root_name) in providers {
            for to_identity in [false, true] {
                let held = real_data_dir();
                let data = held.path();
                std::fs::create_dir(data.join("identity")).expect("identity");
                let root = data.join(root_name);
                std::fs::remove_dir(&root).expect(root_name);
                let target = if to_identity {
                    data.join("identity")
                } else {
                    data.to_path_buf()
                };
                std::os::unix::fs::symlink(&target, &root).expect("symlink");
                let error = super::super::os_entry::render_helper_confinement(
                    component,
                    data,
                    Path::new(EXE),
                    5,
                )
                .expect_err("a symlinked root must be refused at render");
                assert!(
                    error.contains(root_name) && error.contains("is a symlink"),
                    "{component} to_identity={to_identity}: {error}"
                );
            }
        }
    }
}
