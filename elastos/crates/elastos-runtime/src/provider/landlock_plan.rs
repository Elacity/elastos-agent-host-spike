//! Landlock file decisions for one provider launch; attachment comes later.
#![allow(dead_code)] // The spawn caller is added in a later slice.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use std::{io, path::PathBuf};

// The lab's STORAGE_ROOT, executable, and ABI-5 handled masks (confine.rs:8560-8582, 8685).
const STORAGE: u64 = 0x41be;
const BINARY: u64 = 0x5;
const HANDLED: u64 = 0xffff;
const NO_LANDLOCK: &str = "linux confinement refused: the kernel has no Landlock";

#[derive(Clone, Copy, Debug)]
enum LoaderArch {
    X86_64,
    Aarch64,
}

impl LoaderArch {
    fn host() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else {
            Self::Aarch64
        }
    }
}

const X86_64_LOADERS: &[&str] = &[
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
];
const AARCH64_LOADERS: &[&str] = &[
    "/lib/ld-linux-aarch64.so.1",
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib/aarch64-linux-gnu/libgcc_s.so.1",
];

fn loader_paths(provider: RuntimeProviderId, arch: LoaderArch) -> Vec<&'static str> {
    let mut paths = match arch {
        LoaderArch::X86_64 => X86_64_LOADERS.to_vec(),
        LoaderArch::Aarch64 => AARCH64_LOADERS.to_vec(),
    };
    match (provider, arch) {
        (RuntimeProviderId::Model, LoaderArch::X86_64) => {
            paths.push("/lib/x86_64-linux-gnu/libm.so.6");
        }
        (RuntimeProviderId::Model | RuntimeProviderId::Wallet, LoaderArch::Aarch64) => {
            paths.push("/lib/aarch64-linux-gnu/libm.so.6");
        }
        _ => {}
    }
    paths
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PathRule(pub &'static str, pub PathBuf, pub u64);
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub abi: u32,
    pub handled: u64,
    pub rules: Vec<PathRule>,
    /// Device and inode of the storage directory opened before launch.
    pub storage_dev: u64,
    pub storage_ino: u64,
}

/// The storage directory opened before launch, with that directory's identity.
#[cfg(target_os = "linux")]
pub(super) struct StorageRoot<'a> {
    pub path: &'a std::path::Path,
    pub dev: u64,
    pub ino: u64,
}

pub(super) struct Bindings {
    pub storage_root: PathBuf,
    pub provider_executable: PathBuf,
    pub storage_dev: u64,
    pub storage_ino: u64,
}

pub(super) fn require_abi(reported: io::Result<u32>) -> Result<u32, String> {
    let abi = reported.map_err(|_| NO_LANDLOCK.to_string())?;
    if abi < 3 {
        return Err(format!("linux confinement refused: the Landlock ABI cannot express the (allow file-read* file-write* (subpath (param \"STORAGE_ROOT\"))) row, which needs ABI 3 and this kernel reports ABI {abi}"));
    }
    if abi < 5 {
        return Err(format!("linux confinement refused: the Landlock ABI cannot express the default-denial file rights, which needs ABI 5 and this kernel reports ABI {abi}"));
    }
    Ok(abi)
}

#[cfg(target_os = "linux")]
fn query_abi() -> io::Result<u32> {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, 1u32) };
    if abi < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(abi as u32)
    }
}
#[cfg(not(target_os = "linux"))]
fn query_abi() -> io::Result<u32> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
pub(super) fn kernel_abi() -> Result<u32, String> {
    require_abi(query_abi())
}

pub(super) fn build(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    bindings: &Bindings,
    abi: u32,
) -> Result<Plan, String> {
    build_for_arch(provider, admitted, bindings, LoaderArch::host(), abi)
}

fn build_for_arch(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    bindings: &Bindings,
    arch: LoaderArch,
    abi: u32,
) -> Result<Plan, String> {
    let abi = require_abi(Ok(abi))?;
    let mut rules = Vec::new();
    // Path rules come from the admitted rows. Loader paths stay with the provider.
    for row in admitted.rows() {
        for form in row.rules {
            match *form {
                r#"(allow file-read* (literal (param "STORAGE_PARENT")))"# => {}
                r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"# => rules.push(
                    PathRule("STORAGE_ROOT", bindings.storage_root.clone(), STORAGE),
                ),
                r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"# => {
                    rules.push(PathRule(
                        "PROVIDER_EXECUTABLE",
                        bindings.provider_executable.clone(),
                        BINARY,
                    ))
                }
                _ => return Err(format!("Landlock has no path decision for {form}")),
            }
        }
    }
    for path in loader_paths(provider, arch) {
        rules.push(PathRule("LANDLOCK_LOADER_PATHS", path.into(), BINARY));
    }
    Ok(Plan {
        abi,
        handled: HANDLED,
        rules,
        storage_dev: bindings.storage_dev,
        storage_ino: bindings.storage_ino,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use RuntimeProviderId::*;

    const LAB: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../capsules/wallet-provider/tests/confine.rs"
    ));

    fn lab_section<'a>(source: &'a str, marker: &str) -> &'a str {
        let start = source
            .find(marker)
            .unwrap_or_else(|| panic!("missing {marker}"));
        source[start..].split_once("];").unwrap().0
    }

    fn lab_bits() -> HashMap<&'static str, u64> {
        let mut bits = HashMap::new();
        for line in LAB
            .lines()
            .filter(|line| line.starts_with("const LANDLOCK_ACCESS_FS_"))
        {
            let (name, shift) = line.split_once(": u64 = 1 << ").unwrap();
            let name = name.strip_prefix("const ").unwrap();
            bits.insert(
                name,
                1 << shift.trim_end_matches(';').parse::<u32>().unwrap(),
            );
        }
        bits
    }

    fn lab_masks() -> (HashMap<String, u64>, u64) {
        let bits = lab_bits();
        let forms: Vec<_> = lab_section(LAB, "const SHARED_RULES: [&str; 3]")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("r#\"")?.strip_suffix("\"#,"))
            .collect();
        let table = lab_section(LAB, "const LANDLOCK_RULE_RIGHTS: &[(&str, u64)]");
        let mut masks = HashMap::new();
        for (index, form) in forms.iter().enumerate() {
            let marker = format!("SHARED_RULES[{index}]");
            let row = table
                .split_once(&marker)
                .unwrap()
                .1
                .split_once("),")
                .unwrap()
                .0;
            let mask = row
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter_map(|token| bits.get(token))
                .fold(0, |mask, bit| mask | bit);
            masks.insert((*form).to_string(), mask);
        }
        let abi_table = lab_section(LAB, "const LANDLOCK_RIGHT_ABI: &[(u64, u32)]");
        let handled = abi_table
            .lines()
            .filter_map(|line| {
                let pair = line.trim().strip_prefix("(LANDLOCK_ACCESS_FS_")?;
                let (name, abi) = pair.split_once(", ")?;
                (abi.trim_end_matches("),").parse::<u32>().unwrap() <= 5)
                    .then(|| bits[format!("LANDLOCK_ACCESS_FS_{name}").as_str()])
            })
            .fold(0, |mask, bit| mask | bit);
        (masks, handled)
    }

    fn lab_loaders(provider: RuntimeProviderId, arch: LoaderArch) -> Vec<PathBuf> {
        fn paths(section: &str) -> Vec<PathBuf> {
            section
                .lines()
                .filter_map(|line| {
                    let first = line.trim().strip_prefix('"')?;
                    first.split_once('"').map(|(path, _)| path.into())
                })
                .filter(|path: &PathBuf| path.to_str().unwrap().starts_with("/lib"))
                .collect()
        }
        let shared: Vec<_> = LAB
            .match_indices("const LANDLOCK_LOADER_PATHS: &[(&str, &str)]")
            .collect();
        let extra: Vec<_> = LAB
            .match_indices("const LIBM_LANDLOCK_LOADER_PATHS: &[(&str, &str)]")
            .collect();
        let index = match arch {
            LoaderArch::Aarch64 => 0,
            LoaderArch::X86_64 => 1,
        };
        let mut result = paths(lab_section(
            &LAB[shared[index].0..],
            "const LANDLOCK_LOADER_PATHS",
        ));
        let users = match arch {
            LoaderArch::Aarch64 => lab_section(LAB, "const LIBM_LOADER_USERS_AARCH64:"),
            LoaderArch::X86_64 => lab_section(LAB, "const LIBM_LOADER_USERS_X86_64:"),
        };
        let name = match provider {
            Did => "DID_PROVIDER",
            Wallet => "WALLET_PROVIDER",
            Model => "MODEL_PROVIDER",
        };
        if users.contains(name) {
            result.extend(paths(lab_section(
                &LAB[extra[index].0..],
                "const LIBM_LANDLOCK_LOADER_PATHS",
            )));
        }
        result
    }

    #[test]
    fn abi_decision_matches_lab_refusals() {
        for abi in [1, 2] {
            assert_eq!(require_abi(Ok(abi)), Err(format!("linux confinement refused: the Landlock ABI cannot express the (allow file-read* file-write* (subpath (param \"STORAGE_ROOT\"))) row, which needs ABI 3 and this kernel reports ABI {abi}")));
        }
        assert_eq!(require_abi(Ok(3)), Err("linux confinement refused: the Landlock ABI cannot express the default-denial file rights, which needs ABI 5 and this kernel reports ABI 3".to_string()));
        assert_eq!(require_abi(Ok(4)), Err("linux confinement refused: the Landlock ABI cannot express the default-denial file rights, which needs ABI 5 and this kernel reports ABI 4".to_string()));
        assert_eq!(
            require_abi(Err(io::Error::other("query failed"))),
            Err("linux confinement refused: the kernel has no Landlock".to_string())
        );
        for abi in [5, 6, 8] {
            assert_eq!(require_abi(Ok(abi)), Ok(abi));
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(query_abi().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[rustfmt::skip]
    fn landlock_blocks(src: &str) -> String {
        let mut out = String::new();
        for marker in ["const SHARED_RULES:", "const LANDLOCK_RULE_RIGHTS:", "const LANDLOCK_RIGHT_ABI:", "fn landlock_loader_paths", "const LANDLOCK_LOADER_PATHS:", "const LIBM_"] {
            let mut rest = src;
            while let Some(at) = rest.find(marker) {
                let slice = &rest[at..];
                let end = if marker.starts_with("fn") { slice.find("\n}").expect("pin d0dd5693 loader") + 2 } else { slice.find("];").expect("pin d0dd5693 table") + 2 };
                out.push_str(&slice[..end]); out.push('\n');
                if !(marker.contains("LOADER_PATHS") || marker.contains("LIBM_")) { break; }
                rest = &slice[end..];
            }
        }
        for line in src.lines().filter(|line| line.starts_with("const LANDLOCK_ACCESS_FS_")) { out.push_str(line); out.push('\n'); }
        out
    }

    #[rustfmt::skip]
    #[test]
    fn landlock_tables_match_pin_d0dd5693() {
        let spec = "d0dd5693:capsules/wallet-provider/tests/confine.rs";
        let out = crate::provider::rights::git_show(spec);
        assert!(out.status.success(), "pin {spec} missing: {}", String::from_utf8_lossy(&out.stderr));
        let pinned = String::from_utf8(out.stdout).expect("pin d0dd5693");
        assert_eq!(landlock_blocks(LAB), landlock_blocks(&pinned), "moved Landlock tables at pin d0dd5693");
    }

    #[rustfmt::skip]
    #[test]
    fn provider_plans_match_lab_file_rows() {
        let (masks, handled) = lab_masks();
        // Same Bindings both sides. Paths stay unchanged: no canonicalization.
        // Projections are separate and in order: paths, masks, then handled.
        for provider in [Did, Wallet, Model] {
            let name = match provider {
                Did => "did-provider",
                Wallet => "wallet-provider",
                Model => "model-provider",
            };
            let fixture = format!(
                "{}/../../../capsules/{name}/tests/fixtures/confine/declared-rights.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let declared: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(fixture).unwrap()).unwrap();
            let bindings = Bindings {
                storage_root: format!("/provider/{provider:?}").into(),
                provider_executable: format!("/bin/{provider:?}").into(),
                storage_dev: 7,
                storage_ino: 9,
            };
            let admitted = super::super::rights::admit_committed(provider);
            for arch in [LoaderArch::X86_64, LoaderArch::Aarch64] {
                let plan = build_for_arch(provider, &admitted, &bindings, arch, 5).unwrap();
                assert_eq!(plan.abi, 5, "{name} {arch:?} abi");
                assert_eq!((plan.storage_dev, plan.storage_ino), (bindings.storage_dev, bindings.storage_ino), "the plan keeps the storage identity");
                let mut expected = Vec::new();
                for claim in declared["rights"].as_array().unwrap() {
                    for form in claim["rules"].as_array().unwrap() {
                        let form = form.as_str().unwrap();
                        let mask = masks[form];
                        if mask == 0 {
                            continue;
                        }
                        let (parameter, path) = if form.contains("STORAGE_ROOT") {
                            ("STORAGE_ROOT", bindings.storage_root.clone())
                        } else if form.contains("PROVIDER_EXECUTABLE") {
                            ("PROVIDER_EXECUTABLE", bindings.provider_executable.clone())
                        } else {
                            panic!("lab form has no bound path: {form}");
                        };
                        expected.push(PathRule(parameter, path, mask));
                    }
                }
                let executable_mask = masks[declared["rights"][1]["rules"][0].as_str().unwrap()];
                for path in lab_loaders(provider, arch) {
                    expected.push(PathRule("LANDLOCK_LOADER_PATHS", path, executable_mask));
                }
                assert_eq!(plan.rules.iter().map(|rule| (rule.0, rule.1.clone())).collect::<Vec<_>>(), expected.iter().map(|rule| (rule.0, rule.1.clone())).collect::<Vec<_>>(), "{name} {arch:?} paths");
                assert_eq!(plan.rules.iter().map(|rule| (rule.0, rule.2)).collect::<Vec<_>>(), expected.iter().map(|rule| (rule.0, rule.2)).collect::<Vec<_>>(), "{name} {arch:?} masks");
                assert_eq!(plan.handled, handled, "{name} {arch:?} handled");
                if std::mem::discriminant(&arch) == std::mem::discriminant(&LoaderArch::host()) {
                    assert_eq!(
                        build(provider, &admitted, &bindings, 5).unwrap().rules,
                        expected
                    );
                }
            }
        }
    }
}
