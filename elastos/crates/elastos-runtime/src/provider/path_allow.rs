//! File allow-list for localhost and object.
//!
//! A single `STORAGE_ROOT` of the data directory would include
//! `identity/device.key`. Each helper gets its own child directories instead.
//! Each of those directories must already exist, be owned by the current user,
//! and must not be a symlink. `spawn_path_allow` starts localhost, object,
//! and chain. Chain's resolver files are read-only and are not a storage
//! root. The single-root `spawn_confined` does not start these helpers.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One rendered helper confinement. `landlock` is the path-beneath plan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HelperConfinement {
    pub seatbelt: String,
    pub landlock_abi: u32,
    pub landlock_handled: u64,
    pub landlock: Vec<super::landlock_plan::PathRule>,
    /// Data directory, its ancestors, and for object the `ElastOS` directory
    /// itself. Seatbelt `file-read-metadata` literals only. They are not
    /// Landlock rules: a path-beneath rule here would include
    /// `identity/device.key`.
    pub metadata: Vec<PathBuf>,
}

/// Object file roots. The seatbelt parameter is the first name. The directory
/// is the second. Seatbelt parameter names cannot contain `/`, so
/// `ElastOS_System` is the parameter for `ElastOS/System` and `LibraryIndex`
/// is the parameter for `ElastOS/SystemServices/Library`.
///
/// `Users` and `UsersAI` hold caller-chosen object names. Object's ElastOS
/// root is `ElastOS/System`, the directory its auth state, lock file, and
/// temp files use. The published-CID index is the only file under
/// `ElastOS/SystemServices/Library`. That directory is this helper's own
/// rule. Home creates it before the helper starts and leaves it owner-only.
/// Nothing else under `ElastOS/SystemServices` is an object root.
///
/// Linux Landlock cannot exclude a child of a granted directory. Localhost
/// still grants `ElastOS`, so `ElastOS/SystemServices/Wallet` stays inside
/// that grant on Linux. macOS adds a Seatbelt deny for that wallet directory
/// after the `ElastOS` allow. The object helper does not grant `ElastOS`.
const OBJECT_ROOTS: &[(&str, &str)] = &[
    ("ElastOS_System", "ElastOS/System"),
    ("Users", "Users"),
    ("UsersAI", "UsersAI"),
    ("LibraryIndex", "ElastOS/SystemServices/Library"),
];

/// macOS localhost deny. Not a Landlock rule: Linux cannot exclude this child.
/// Seatbelt rejects a `subpath` whose directory does not exist, so the macOS
/// launch creates this directory before `sandbox-exec` when it is missing.
const LOCALHOST_WALLET_DENY: &str =
    "(deny file-read* file-write* (subpath (param \"ELASTOS_WALLET\")))\n";
#[cfg(test)]
const LOCALHOST_WALLET_PARAM: &str = "ELASTOS_WALLET";
#[cfg(target_os = "macos")]
const LOCALHOST_WALLET_RELATIVE: &str = "ElastOS/SystemServices/Wallet";

/// `node_lifecycle_state_path` joins this directory under the data directory.
const CHAIN_ROOTS: &[&str] = &["chain-provider"];

/// Localhost serves a caller-chosen path under any file-backed root, so it
/// needs all seven: AppCapsules, ElastOS, Local, MyWebSite, Public, Users,
/// and UsersAI.
/// `(seatbelt parameter, directory under the data directory)`.
fn root_specs(provider: RuntimeProviderId) -> Vec<(&'static str, &'static str)> {
    match provider {
        RuntimeProviderId::Localhost => elastos_common::localhost::FILE_BACKED_ROOTS
            .iter()
            .map(|name| (*name, *name))
            .collect(),
        RuntimeProviderId::Object => OBJECT_ROOTS.to_vec(),
        RuntimeProviderId::Chain => CHAIN_ROOTS.iter().map(|name| (*name, *name)).collect(),
        RuntimeProviderId::Did | RuntimeProviderId::Wallet | RuntimeProviderId::Model => Vec::new(),
    }
}

/// The wallet directory localhost's macOS profile denies. Linux does not use
/// this path as an exclusion. The macOS launch creates it when it is missing.
#[cfg(target_os = "macos")]
pub(super) fn localhost_wallet_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCALHOST_WALLET_RELATIVE)
}

/// Create `ElastOS/SystemServices/Wallet` when it is missing, at mode 0700.
/// Seatbelt will not install a `subpath` deny for a path that does not exist,
/// and that abort would stop localhost. An existing directory is left as it
/// is. A symlink or a non-directory on the path is refused.
#[cfg(target_os = "macos")]
pub(super) fn ensure_localhost_wallet_dir(data_dir: &Path) -> Result<PathBuf, String> {
    ensure_nested_directory(data_dir, LOCALHOST_WALLET_RELATIVE)?;
    Ok(localhost_wallet_dir(data_dir))
}

/// The data directory and every ancestor except `/`, for both the path the
/// caller passed and its canonical path. `/` already has `file-read*`.
fn metadata_literals(data_dir: &Path) -> Result<Vec<PathBuf>, String> {
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
fn require_real_root(
    data_dir: &Path,
    name: &str,
    path: &Path,
    nested: bool,
) -> Result<(u64, u64, std::os::fd::OwnedFd), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| format!("provider start is refused: {name} is missing. Create a directory named {name} that you own in the data directory, then start Home again."))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("provider start is refused: {name} is a symlink"));
    }
    if !metadata.is_dir() {
        return Err(format!("provider start is refused: {name} is not a directory. Replace it with a directory you own, then start Home again."));
    }
    if metadata.uid() != current_user() {
        return Err(format!("provider start is refused: {name} is not owned by the current user. Give {name} to this user, or replace it with a directory this user owns, then start Home again."));
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
    let inside = if nested {
        resolved.starts_with(&data_resolved) && resolved != data_resolved
    } else {
        resolved.parent() == Some(data_resolved.as_path())
    };
    if !inside {
        return Err(format!(
            "provider start is refused: {name} resolves outside the data directory"
        ));
    }
    // Open the directory now and hold it until the rule is added. A later
    // name at this path is a different inode. The opened identity has to be
    // the identity just checked.
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("provider start is refused: {name} contains NUL"))?;
    let held = super::root_pin::hold_directory(&c_path).map_err(|errno| {
        format!("provider start is refused: {name} could not be held open (errno {errno})")
    })?;
    let opened = std::fs::File::from(held);
    let opened_meta = opened.metadata().map_err(|error| {
        format!("provider start is refused: {name} could not be stated: {error}")
    })?;
    if opened_meta.dev() != metadata.dev() || opened_meta.ino() != metadata.ino() {
        return Err(format!(
            "provider start is refused: {name} changed while it was checked"
        ));
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        std::os::fd::OwnedFd::from(opened),
    ))
}

fn resolve_roots(
    provider: RuntimeProviderId,
    data_dir: &Path,
) -> Result<Vec<super::landlock_plan::AllowRoot>, String> {
    if !data_dir.is_absolute() {
        return Err(
            "provider start is refused: the data directory path is not absolute".to_string(),
        );
    }
    let specs = root_specs(provider);
    if specs.is_empty() {
        return Err("provider start is refused: the path allow-list has no file roots".to_string());
    }
    let mut resolved: Vec<super::landlock_plan::AllowRoot> = Vec::with_capacity(specs.len());
    for (param, relative) in specs {
        if relative.contains('/') {
            ensure_nested_directory(data_dir, relative)?;
        }
        let path = data_dir.join(relative);
        let (dev, ino, held) =
            require_real_root(data_dir, relative, &path, relative.contains('/'))?;
        resolved.push(super::landlock_plan::AllowRoot {
            name: param,
            path,
            dev,
            ino,
            held: Some(held),
        });
    }
    Ok(resolved)
}

/// Create each missing component of `relative` at mode 0700. A symlink or a
/// non-directory on that path is refused. Open each one without following a link, at 0700.
fn ensure_nested_directory(data_dir: &Path, relative: &str) -> Result<(), String> {
    let mut current = data_dir.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!(
                "provider start is refused: {relative} resolves outside the data directory"
            ));
        }
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "provider start is refused: {relative} is a symlink"
                ));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(format!(
                    "provider start is refused: {relative} is not a directory. Replace it with a directory you own, then start Home again."
                ));
            }
            Ok(_) => elastos_common::localhost::private_dir(&current, relative, false)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                elastos_common::localhost::private_dir(&current, relative, true)?;
            }
            Err(err) => {
                return Err(format!(
                    "provider start is refused: {relative} could not be created: {err}"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn render_with_plan(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    data_dir: &Path,
    executable: &Path,
    landlock_abi: u32,
) -> Result<(HelperConfinement, super::landlock_plan::Plan), String> {
    let storage = admitted.admits("storage");
    let executable_right = admitted.admits("bound-executable");
    let mut roots = if storage {
        resolve_roots(provider, data_dir)?
    } else {
        Vec::new()
    };
    if reaches_device_key(data_dir, executable) {
        return Err(
            "provider start is refused: the executable path reaches identity/device.key"
                .to_string(),
        );
    }
    let names: Vec<&str> = roots.iter().map(|root| root.name).collect();
    let chain = matches!(provider, RuntimeProviderId::Chain);
    // Chain's measured profile has no ancestor metadata. The data directory
    // stays out of the Seatbelt text, so identity/device.key stays unreadable.
    // A grant without storage has no file roots and no metadata literals.
    let mut metadata = if chain || !storage {
        Vec::new()
    } else {
        metadata_literals(data_dir)?
    };
    if matches!(provider, RuntimeProviderId::Object) && storage {
        // The auth-state walk stats `ElastOS` on the way to `ElastOS/System/Auth`.
        // That directory is not a root. A metadata literal lets the walk reject
        // a symlink there. It does not grant the other children of `ElastOS`.
        // Linux Landlock does not mediate stat, so the Landlock plan stays
        // `ElastOS/System` and still cannot exclude a child of a granted directory.
        let elast = data_dir.join("ElastOS");
        if !metadata.iter().any(|path| path == &elast) {
            metadata.push(elast);
        }
    }
    let mut seatbelt = super::macos_profile::render_path_allow_profile(
        &names,
        metadata.len(),
        chain,
        storage,
        executable_right,
    )?;
    if storage && matches!(provider, RuntimeProviderId::Localhost) {
        // After the ElastOS allow. Last-match Seatbelt denies the wallet
        // directory. An exec-only grant has no file root, so it does not get
        // this subpath. Linux Landlock cannot exclude that child; this line is
        // macOS only and is not a Landlock rule.
        seatbelt.push_str(LOCALHOST_WALLET_DENY);
    }
    let plan = super::landlock_plan::build_path_allow_plan(
        provider,
        admitted,
        &mut roots,
        executable,
        landlock_abi,
    )?;
    if plan
        .rules
        .iter()
        .any(|rule| reaches_device_key(data_dir, &rule.1))
    {
        return Err(
            "provider start is refused: the Landlock plan reaches identity/device.key".to_string(),
        );
    }
    Ok((
        HelperConfinement {
            seatbelt,
            landlock_abi: plan.abi,
            landlock_handled: plan.handled,
            landlock: plan.rules.clone(),
            metadata,
        },
        plan,
    ))
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
#[cfg(test)]
mod tests {
    use std::path::Path;
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;

    const EXE: &str = "/opt/elastos/helper-provider";

    fn render(
        component_key: &str,
        data_dir: &Path,
        executable: &Path,
        abi: u32,
    ) -> Result<super::HelperConfinement, String> {
        let provider = super::super::rights_table::RuntimeProviderId::path_allow(component_key)
            .ok_or_else(|| {
                format!(
                    "provider start is refused: component key \"{component_key}\" has no path allow-list"
                )
            })?;
        let admitted = super::super::rights::admit_runtime_grant(provider);
        Ok(super::render_with_plan(provider, &admitted, data_dir, executable, abi)?.0)
    }

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
            (
                "object-provider",
                &["ElastOS_System", "Users", "UsersAI", "LibraryIndex"],
            ),
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
            let rendered = render(component_key, data_dir, executable, 5)
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
                if *component_key == "object-provider" {
                    assert!(
                        rendered
                            .metadata
                            .iter()
                            .any(|path| path == &data_dir.join("ElastOS")),
                        "object stats ElastOS itself so the auth walk can reject a symlink"
                    );
                }
            }
            assert!(rendered
                .metadata
                .iter()
                .all(|path| { path != Path::new("/") && path != &key && path != &identity }));
            assert!(!rendered
                .landlock
                .iter()
                .any(|rule| rendered.metadata.iter().any(|path| path == &rule.1)));
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
            if *component_key == "localhost-provider" {
                assert!(
                    rendered
                        .seatbelt
                        .contains(super::LOCALHOST_WALLET_DENY.trim()),
                    "localhost macOS profile denies the wallet directory"
                );
                assert_eq!(
                    subpaths.last().copied(),
                    Some(super::LOCALHOST_WALLET_PARAM)
                );
                subpaths.pop();
                assert!(
                    rendered
                        .landlock
                        .iter()
                        .any(|rule| rule.1.ends_with("ElastOS")),
                    "Linux still grants ElastOS; Landlock cannot exclude the wallet child"
                );
                assert!(
                    !rendered
                        .landlock
                        .iter()
                        .any(|rule| rule.0 == super::LOCALHOST_WALLET_PARAM),
                    "the wallet deny is not a Landlock rule"
                );
            }
            if *component_key == "object-provider" {
                assert!(
                    rendered.landlock.iter().any(
                        |rule| rule.0 == "ElastOS_System" && rule.1.ends_with("ElastOS/System")
                    ),
                    "object grants ElastOS/System"
                );
                assert!(
                    !rendered
                        .landlock
                        .iter()
                        .any(|rule| rule.1 == data_dir.join("ElastOS")),
                    "object no longer grants all of ElastOS"
                );
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
                rule.0 != "PROVIDER_EXECUTABLE"
                    && rule.0 != "LANDLOCK_LOADER_PATHS"
                    && rule.0 != "READ_ONLY_FILE"
            });
            let resolver: Vec<_> = rendered
                .landlock
                .iter()
                .filter(|rule| rule.0 == "READ_ONLY_FILE")
                .collect();
            if chain {
                const ALLOWED: &[&str] = &["/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"];
                for rule in &resolver {
                    let path = rule.1.to_str().unwrap();
                    assert!(ALLOWED.contains(&path), "{path}");
                    assert_eq!(rule.2, 4, "{path}");
                    assert!(!rule.1.starts_with(data_dir));
                }
            } else {
                assert!(resolver.is_empty(), "{component_key} gained resolver files");
            }
            assert_eq!(roots.len(), expected.len(), "{component_key} root count");
            for (rule, name) in roots.iter().zip(expected.iter()) {
                let relative = match *name {
                    "ElastOS_System" => "ElastOS/System",
                    "LibraryIndex" => "ElastOS/SystemServices/Library",
                    other => other,
                };
                let path = data_dir.join(relative);
                assert_eq!(rule.0, *name, "{component_key}");
                assert_eq!(rule.1, path, "{component_key}");
                assert!(
                    rule.1.starts_with(data_dir) && rule.1 != data_dir,
                    "allow list grew to the whole data directory: {:?}",
                    rule.1
                );
                if *name == "ElastOS_System" {
                    assert_eq!(
                        rule.1.parent().and_then(|parent| parent.parent()),
                        Some(data_dir)
                    );
                } else if *name == "LibraryIndex" {
                    assert_eq!(
                        rule.1
                            .parent()
                            .and_then(|parent| parent.parent())
                            .and_then(|parent| parent.parent()),
                        Some(data_dir)
                    );
                } else {
                    assert_eq!(rule.1.parent(), Some(data_dir));
                }
                assert!(
                    !reaches(&rule.1, &key) && !reaches(&rule.1, &identity),
                    "{component_key} reaches the device key through {}",
                    rule.1.display()
                );
                assert_eq!(rule.2, storage_mask, "{component_key} mask");
            }
            let executable_rules: Vec<_> = rest
                .iter()
                .filter(|rule| rule.0 == "PROVIDER_EXECUTABLE")
                .collect();
            assert_eq!(executable_rules.len(), 1, "{component_key} executable");
            assert_eq!(executable_rules[0].1, executable);
            assert_eq!(executable_rules[0].2, binary_mask);
            let loaders: Vec<_> = rest
                .iter()
                .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
                .map(|rule| rule.1.clone())
                .collect();
            assert_eq!(loaders, did_loaders, "{component_key} loaders");
            for rule in &rendered.landlock {
                assert!(
                    !reaches(&rule.1, &key) && !reaches(&rule.1, &identity),
                    "{component_key} Landlock rule {} reaches the device key",
                    rule.1.display()
                );
                assert_ne!(
                    rule.1, data_dir,
                    "allow list grew to the whole data directory"
                );
                if *component_key == "object-provider" {
                    let text = rule.1.to_string_lossy();
                    assert!(
                        !text.ends_with("SystemServices")
                            && !text.contains("SystemServices/Wallet")
                            && !text.contains("SystemServices/Content"),
                        "{component_key} granted {text}"
                    );
                }
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

        let refused = render("wallet-provider", data_dir, executable, 5);
        assert!(refused.is_err(), "wallet stays on its single-root profile");
    }

    #[test]
    fn object_system_root_is_created_when_the_home_has_no_elastos_directory() {
        use std::os::unix::fs::PermissionsExt;
        let held = tempfile::tempdir().expect("data directory");
        let data = held.path();
        std::fs::create_dir(data.join("Users")).unwrap();
        std::fs::create_dir(data.join("UsersAI")).unwrap();
        assert!(!data.join("ElastOS").exists());
        let rendered = render("object-provider", data, Path::new(EXE), 5)
            .expect("a missing ElastOS/System is created");
        let system = data.join("ElastOS/System");
        let meta = std::fs::symlink_metadata(&system).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let library = data.join("ElastOS/SystemServices/Library");
        let library_meta = std::fs::symlink_metadata(&library).unwrap();
        assert!(library_meta.is_dir());
        assert_eq!(library_meta.permissions().mode() & 0o777, 0o700);
        assert!(!data.join("ElastOS/SystemServices/Wallet").exists());
        assert!(rendered.landlock.iter().any(|rule| rule.1 == system));
        assert!(rendered.landlock.iter().any(|rule| rule.1 == library));
    }

    #[test]
    fn an_existing_library_index_is_narrowed_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let held = tempfile::tempdir().expect("data directory");
        let data = held.path();
        std::fs::create_dir(data.join("Users")).unwrap();
        std::fs::create_dir(data.join("UsersAI")).unwrap();
        let library = data.join("ElastOS/SystemServices/Library");
        std::fs::create_dir_all(&library).unwrap();
        std::fs::set_permissions(&library, std::fs::Permissions::from_mode(0o755)).unwrap();
        render("object-provider", data, Path::new(EXE), 5).expect("existing Library is narrowed");
        let mode = |path: &std::path::Path| {
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        let services = data.join("ElastOS/SystemServices");
        assert_eq!(mode(&library), 0o700);
        assert_eq!(mode(&services), 0o700);
        std::fs::set_permissions(&services, std::fs::Permissions::from_mode(0o755)).unwrap();
        render("object-provider", data, Path::new(EXE), 5).expect("a second start narrows again");
        assert_eq!(mode(&library), 0o700);
        assert_eq!(mode(&services), 0o700);
        assert!(!data.join("ElastOS/SystemServices/Wallet").exists());
    }

    #[cfg(target_os = "macos")]
    fn seatbelt_defines(
        rendered: &super::HelperConfinement,
        data: &Path,
        wallet: &Path,
    ) -> Vec<(String, PathBuf)> {
        let mut names = Vec::new();
        for line in rendered.seatbelt.lines() {
            if let Some(name) = quoted(line, "(param \"") {
                if !names.iter().any(|seen| seen == name) {
                    names.push(name.to_string());
                }
            }
        }
        names
            .into_iter()
            .map(|name| {
                let path = if name == "ElastOS_System" {
                    data.join("ElastOS/System")
                } else if name == "LibraryIndex" {
                    data.join("ElastOS/SystemServices/Library")
                } else if name == "ELASTOS_WALLET" {
                    wallet.to_path_buf()
                } else if name == "PROVIDER_EXECUTABLE" {
                    PathBuf::from("/bin/cat")
                } else if let Some(rest) = name.strip_prefix("META_") {
                    rendered.metadata[rest.parse::<usize>().unwrap()].clone()
                } else {
                    data.join(&name)
                };
                (name, path)
            })
            .collect()
    }

    #[cfg(target_os = "macos")]
    fn sandboxed_cat(
        rendered: &super::HelperConfinement,
        defines: &[(String, PathBuf)],
        file: &Path,
    ) -> std::process::Output {
        let mut command = std::process::Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&rendered.seatbelt);
        for (name, path) in defines {
            command.arg("-D").arg(format!("{name}={}", path.display()));
        }
        command
            .arg("/bin/cat")
            .arg(file)
            .output()
            .expect("sandbox-exec")
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn localhost_seatbelt_denies_the_wallet_directory() {
        let held = real_data_dir();
        let data = held.path();
        let note_dir = data.join("ElastOS/System");
        std::fs::create_dir_all(&note_dir).unwrap();
        let note = note_dir.join("note.txt");
        std::fs::write(&note, b"readable").unwrap();
        let wallet = super::localhost_wallet_dir(data);
        std::fs::create_dir_all(&wallet).unwrap();
        let secret = wallet.join("wallet-key.hex");
        std::fs::write(&secret, b"wallet-secret").unwrap();
        let data = std::fs::canonicalize(data).unwrap();
        let note = data.join("ElastOS/System/note.txt");
        let wallet = super::localhost_wallet_dir(&data);
        let secret = wallet.join("wallet-key.hex");
        let rendered = render("localhost-provider", &data, Path::new(EXE), 5).unwrap();
        let defines = seatbelt_defines(&rendered, &data, &wallet);
        let denied = sandboxed_cat(&rendered, &defines, &secret);
        assert!(
            !denied.status.success(),
            "wallet file was readable: {}",
            String::from_utf8_lossy(&denied.stdout)
        );
        assert_eq!(std::fs::read(&secret).unwrap(), b"wallet-secret");
        let allowed = sandboxed_cat(&rendered, &defines, &note);
        assert!(
            allowed.status.success(),
            "ElastOS/System/note.txt must stay readable: {} {}",
            String::from_utf8_lossy(&allowed.stderr),
            String::from_utf8_lossy(&allowed.stdout)
        );
        assert_eq!(allowed.stdout, b"readable");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn localhost_seatbelt_creates_a_missing_wallet_directory_and_denies_it() {
        use std::os::unix::fs::PermissionsExt;
        let held = real_data_dir();
        let data = std::fs::canonicalize(held.path()).unwrap();
        let note_dir = data.join("ElastOS/System");
        std::fs::create_dir_all(&note_dir).unwrap();
        let note = note_dir.join("note.txt");
        std::fs::write(&note, b"readable").unwrap();
        let wallet = super::localhost_wallet_dir(&data);
        assert!(!wallet.exists(), "the row starts with no wallet directory");
        let created = super::ensure_localhost_wallet_dir(&data).unwrap();
        assert_eq!(created, wallet);
        let meta = std::fs::symlink_metadata(&wallet).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let secret = wallet.join("wallet-key.hex");
        std::fs::write(&secret, b"wallet-secret").unwrap();
        let rendered = render("localhost-provider", &data, Path::new(EXE), 5).unwrap();
        let defines = seatbelt_defines(&rendered, &data, &wallet);
        let denied = sandboxed_cat(&rendered, &defines, &secret);
        assert!(
            !denied.status.success(),
            "a created wallet directory stayed readable"
        );
        let allowed = sandboxed_cat(&rendered, &defines, &note);
        assert!(
            allowed.status.success(),
            "ElastOS/System/note.txt must stay readable: {}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        let launcher = include_str!("os_entry.rs");
        assert!(
            launcher.contains("ensure_localhost_wallet_dir"),
            "deleting the macOS launch call leaves a missing wallet path able to abort sandbox-exec"
        );
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
                let error = render(component, data, Path::new(EXE), 5)
                    .expect_err("a symlinked root must be refused at render");
                assert!(
                    error.contains(root_name) && error.contains("is a symlink"),
                    "{component} to_identity={to_identity}: {error}"
                );
            }
        }
    }

    fn old_home(parent: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let data = parent.join("data");
        std::fs::create_dir_all(data.join("ElastOS")).unwrap();
        for relative in [
            "ElastOS/kept.txt",
            "ElastOS/System/kept.txt",
            "chain-provider/kept.txt",
        ] {
            let path = data.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"kept-from-the-old-home").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        assert!(
            !data.join("UsersAI").exists(),
            "an old home has no UsersAI yet"
        );
        assert!(!data
            .join("capsules/localhost-provider/capsule.json")
            .exists());
        elastos_common::localhost::ensure_file_backed_roots(&data).unwrap();
        assert!(
            data.join("UsersAI").is_dir(),
            "Home creates the missing root"
        );
        data
    }

    fn assert_old_home_fenced(data: &std::path::Path) {
        use std::os::unix::fs::MetadataExt;
        for key in ["localhost-provider", "object-provider", "chain-provider"] {
            let rendered = render(key, data, Path::new(EXE), 5)
                .unwrap_or_else(|err| panic!("{key} at {}: {err}", data.display()));
            let file = match key {
                "chain-provider" => data.join("chain-provider/kept.txt"),
                "object-provider" => data.join("ElastOS/System/kept.txt"),
                _ => data.join("ElastOS/kept.txt"),
            };
            assert!(
                rendered
                    .landlock
                    .iter()
                    .any(|rule| file.starts_with(&rule.1) && rule.1 != data),
                "{key} plan does not cover {} in {:?}",
                file.display(),
                rendered.landlock
            );
        }
        for relative in [
            "ElastOS/kept.txt",
            "ElastOS/System/kept.txt",
            "chain-provider/kept.txt",
        ] {
            let path = data.join(relative);
            let meta = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o640, "{}", path.display());
            assert_eq!(meta.uid(), super::current_user(), "{relative}");
            assert_eq!(std::fs::read(&path).unwrap(), b"kept-from-the-old-home");
        }
    }

    #[test]
    fn an_updated_home_fences_helpers_and_keeps_existing_files() {
        let held = tempfile::tempdir().unwrap();
        let data = old_home(held.path());
        assert_old_home_fenced(&data);

        let link_hold = tempfile::tempdir().unwrap();
        let link = link_hold.path().join("home");
        std::os::unix::fs::symlink(&data, &link).unwrap();
        assert_old_home_fenced(&link);

        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        let tmp_data = old_home(tmp.path());
        let canonical = std::fs::canonicalize(&tmp_data).unwrap();
        assert!(
            canonical.starts_with("/tmp") || canonical.starts_with("/private/tmp"),
            "{}",
            canonical.display()
        );
        assert_old_home_fenced(&tmp_data);
    }

    /// A second writable volume. `cargo test` lists this ignored. Running it
    /// with `--ignored` fences that volume, or fails when the machine has none.
    /// `test-elastos` does not pass `--ignored`, and no CI job has a second
    /// volume, so this test stays unproved. The device comparison is
    /// `a_rendered_plan_with_a_changed_root_dev_is_refused`, which changes
    /// `root_dev` in a rendered plan and does not mount a volume.
    #[test]
    #[ignore = "needs a second writable volume; test-elastos lists this ignored and does not run it"]
    fn an_updated_home_on_another_volume_is_fenced() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root_dev = std::fs::metadata("/").unwrap().dev();
        let mut other = None;
        for mount in ["/dev/shm", "/Volumes", "/mnt", "/media"] {
            let mut candidates = vec![std::path::PathBuf::from(mount)];
            if let Ok(entries) = std::fs::read_dir(mount) {
                candidates.extend(entries.flatten().map(|entry| entry.path()));
            }
            for path in candidates {
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
                if std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).is_err()
                {
                    continue;
                }
                let Ok(probed) = std::fs::symlink_metadata(&probe) else {
                    continue;
                };
                if probed.mode() & 0o777 != 0o640 {
                    continue;
                }
                eprintln!("other-volume {}", path.display());
                other = Some(dir);
                break;
            }
            if other.is_some() {
                break;
            }
        }
        let Some(dir) = other else {
            eprintln!("other-volume none");
            panic!("no second writable volume that keeps unix mode 0640; this test fails instead of passing");
        };
        let data = old_home(dir.path());
        let dev = std::fs::metadata(&data).unwrap().dev();
        assert_ne!(dev, root_dev, "the other volume is the boot volume");
        assert_old_home_fenced(&data);
        eprintln!("other-volume used {}", data.display());
    }

    #[test]
    fn a_missing_root_names_itself_and_what_to_do() {
        let held = real_data_dir();
        std::fs::remove_dir(held.path().join("UsersAI")).unwrap();
        let error = render("localhost-provider", held.path(), Path::new(EXE), 5)
            .expect_err("a missing root is refused");
        assert!(error.contains("UsersAI"), "{error}");
        assert!(
            error.contains("Create a directory named UsersAI"),
            "{error}"
        );
        assert!(error.contains("that you own"), "{error}");
        assert!(error.contains("start Home again"), "{error}");
    }

    #[test]
    fn a_root_that_is_not_a_directory_names_itself_and_what_to_do() {
        let held = real_data_dir();
        let root = held.path().join("Users");
        std::fs::remove_dir(&root).unwrap();
        std::fs::write(&root, b"not-a-directory").unwrap();
        let error = render("object-provider", held.path(), Path::new(EXE), 5)
            .expect_err("a file in place of a root is refused");
        assert!(error.contains("Users"), "{error}");
        assert!(
            error.contains("Replace it with a directory you own"),
            "{error}"
        );
        assert!(error.contains("start Home again"), "{error}");
    }

    #[test]
    fn a_root_owned_by_someone_else_names_itself_and_what_to_do() {
        use std::os::unix::fs::MetadataExt;
        let uid = super::current_user();
        let mut found = None;
        for (parent, name) in [
            ("/usr", "bin"),
            ("/usr", "lib"),
            ("/private", "etc"),
            ("/", "usr"),
        ] {
            let path = std::path::Path::new(parent).join(name);
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() == uid {
                continue;
            }
            found = Some((parent, name, path));
            break;
        }
        let (parent, name, path) =
            found.expect("this machine has no directory owned by another user");
        let error = super::require_real_root(std::path::Path::new(parent), name, &path, false)
            .expect_err("a root owned by someone else is refused");
        assert!(error.contains(name), "{error}");
        assert!(error.contains("not owned by the current user"), "{error}");
        assert!(
            error.contains(&format!("Give {name} to this user")),
            "{error}"
        );
        assert!(error.contains("start Home again"), "{error}");
    }
}
