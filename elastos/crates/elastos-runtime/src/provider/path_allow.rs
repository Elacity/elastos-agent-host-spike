//! File allow-list for localhost, object, and chain.
//!
//! A single `STORAGE_ROOT` of the data directory would include
//! `identity/device.key`. Each helper gets its own child directories instead.
//! `spawn_confined` does not admit these providers yet.

use std::path::{Path, PathBuf};

/// One rendered helper confinement. `landlock` is the path-beneath plan.
#[derive(Debug, PartialEq, Eq)]
pub struct HelperConfinement {
    pub seatbelt: String,
    pub landlock_abi: u32,
    pub landlock_handled: u64,
    pub landlock: Vec<HelperLandlockRule>,
}

/// One Landlock path rule. `mask` is the ABI-5 access bits.
#[derive(Debug, PartialEq, Eq)]
pub struct HelperLandlockRule {
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

fn resolve_roots(
    provider: HelperId,
    data_dir: &Path,
) -> Result<Vec<(&'static str, PathBuf)>, String> {
    if !data_dir.is_absolute() {
        return Err(
            "provider start is refused: the data directory path is not absolute".to_string(),
        );
    }
    let names = file_roots(provider);
    if names.is_empty() {
        return Err("provider start is refused: the path allow-list has no file roots".to_string());
    }
    let mut resolved = Vec::with_capacity(names.len());
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
        if resolved.iter().any(|(seen, _)| *seen == *name) {
            return Err(format!("provider start is refused: {name} is listed twice"));
        }
        resolved.push((*name, path));
    }
    Ok(resolved)
}

pub(super) fn render(
    component_key: &str,
    data_dir: &Path,
    executable: &Path,
    landlock_abi: u32,
) -> Result<HelperConfinement, String> {
    let provider = helper_id(component_key)?;
    let roots = resolve_roots(provider, data_dir)?;
    if reaches_device_key(data_dir, executable) {
        return Err(
            "provider start is refused: the executable path reaches identity/device.key"
                .to_string(),
        );
    }
    let names: Vec<&str> = roots.iter().map(|(name, _)| *name).collect();
    let seatbelt = super::macos_profile::render_path_allow_profile(&names)?;
    if seatbelt.contains("STORAGE_ROOT")
        || seatbelt.contains("STORAGE_PARENT")
        || seatbelt.contains("identity")
    {
        return Err(
            "provider start is refused: the Seatbelt profile names a forbidden path".to_string(),
        );
    }
    let plan = super::landlock_plan::build_path_allow_plan(&roots, executable, landlock_abi)?;
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
    Ok(HelperConfinement {
        seatbelt,
        landlock_abi: plan.abi,
        landlock_handled: plan.handled,
        landlock,
    })
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use std::path::Path;

    const DATA: &str = "/srv/home-data";
    const EXE: &str = "/opt/elastos/helper-provider";
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
        let data_dir = Path::new(DATA);
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
                "{component_key} must stay outside spawn_confined until slice C2"
            );
            let rendered = super::super::os_entry::render_helper_confinement(
                component_key,
                data_dir,
                executable,
                5,
            )
            .unwrap_or_else(|err| panic!("{component_key}: {err}"));
            assert!(rendered
                .seatbelt
                .starts_with("(version 1)\n(deny default)\n(deny network*)\n"));
            assert!(!rendered.seatbelt.contains("(allow network"));
            assert!(!rendered.seatbelt.contains(DATA));
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
                    assert_eq!(path, "/", "{component_key} literal {path}");
                }
            }
            assert_eq!(subpaths, *expected, "{component_key} seatbelt roots");
            assert_eq!(
                literals,
                ["PROVIDER_EXECUTABLE"],
                "{component_key} literals"
            );

            let (roots, rest): (Vec<_>, Vec<_>) = rendered.landlock.iter().partition(|rule| {
                rule.name != "PROVIDER_EXECUTABLE" && rule.name != "LANDLOCK_LOADER_PATHS"
            });
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
}
