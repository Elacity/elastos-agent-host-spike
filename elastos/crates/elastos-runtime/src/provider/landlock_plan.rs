//! Landlock file decisions for one provider launch; attachment comes later.
#![allow(dead_code)] // The spawn caller is added in a later slice.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use std::{
    io,
    path::{Path, PathBuf},
};

// STORAGE is the file-write row (confine.rs). BINARY is execute plus read.
// `handled_fs` is the filesystem mask that ABI defines. ABI 4's TCP rights and
// ABI 6's scope stay in other ruleset fields, which this plan leaves unset.
const STORAGE: u64 = 0x41be;
const BINARY: u64 = 0x5;
/// `LANDLOCK_ACCESS_FS_READ_FILE` (1 << 2). A resolver file is not a storage root.
const READ_FILE: u64 = 4;
/// glibc NSS and the resolver. Optional files stay closed: the note measured
/// `/etc/gai.conf` and `/etc/host.conf` as nonfatal, and glibc 2.39 does not
/// open `ld.so.cache` or `libnss`.
const CHAIN_RESOLVER_FILES: &[&str] = &["/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"];
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PathRule(pub &'static str, pub PathBuf, pub u64);
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub abi: u32,
    pub handled: u64,
    pub rules: Vec<PathRule>,
    /// Device and inode of the storage directory opened before launch.
    /// A helper with no file root leaves these zero. Its directory identities
    /// are `root_dev` and `root_ino`, in rule order.
    pub storage_dev: u64,
    pub storage_ino: u64,
    pub root_dev: Vec<u64>,
    pub root_ino: Vec<u64>,
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

/// Filesystem rights defined at `abi`. Bit 13 is refer (ABI 2), bit 14 is
/// truncate (ABI 3), bit 15 is ioctl on devices (ABI 5).
pub(super) fn handled_fs(abi: u32) -> u64 {
    0x1fff | u64::from(abi >= 2) << 13 | u64::from(abi >= 3) << 14 | u64::from(abi >= 5) << 15
}

/// ABI this provider needs. Truncate stays in `STORAGE` and `renameat2` stays
/// on the storage list, so refer is not subtracted. The literal name `ioctl`
/// is subtracted when the seccomp list does not admit it.
#[rustfmt::skip]
pub(super) fn abi_required(names: &[&str]) -> u32 {
    if names.contains(&"ioctl") { 5 } else if STORAGE & (1 << 14) != 0 { 3 } else { 2 }
}

#[rustfmt::skip]
pub(super) fn require_abi(provider: RuntimeProviderId, admitted: &AdmittedRights, reported: io::Result<u32>) -> Result<u32, String> {
    let arch = if cfg!(target_arch = "x86_64") { super::seccomp_list::AuditArch::X86_64 } else { super::seccomp_list::AuditArch::Aarch64 };
    let needed = abi_required(&super::seccomp_list::linux_seccomp_list(provider, admitted, arch));
    match reported { Ok(abi) if abi >= needed => Ok(abi), Ok(abi) => Err(format!("linux confinement refused: this kernel reports Landlock ABI {abi}; {} needs ABI {needed}", if needed >= 5 { "ioctl on devices" } else { "truncate" })), Err(_) => Err(NO_LANDLOCK.to_string()) }
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
    query_abi().map_err(|_| NO_LANDLOCK.to_string())
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
    let abi = require_abi(provider, admitted, Ok(abi))?;
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
                // macOS probe X4's Metal bundle, X5 and X6 have no Linux path decision.
                r#"(allow file-read* (regex "^/System/Library/Extensions/AGXMetal[A-Za-z0-9_]+\\.bundle(/.*)?$"))"#
                | r#"(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient") (iokit-user-client-class "IOSurfaceRootUserClient"))"#
                | r#"(allow mach-lookup (global-name "com.apple.MTLCompilerService"))"#
                    if matches!(provider, RuntimeProviderId::Model) => {}
                _ => return Err(format!("Landlock has no path decision for {form}")),
            }
        }
    }
    for path in loader_paths(provider, arch) {
        rules.push(PathRule("LANDLOCK_LOADER_PATHS", path.into(), BINARY));
    }
    Ok(Plan {
        abi,
        handled: handled_fs(abi),
        rules,
        storage_dev: bindings.storage_dev,
        storage_ino: bindings.storage_ino,
        root_dev: Vec::new(),
        root_ino: Vec::new(),
    })
}

/// One helper directory, with the device and inode of that directory.
pub(super) struct AllowRoot {
    pub name: &'static str,
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
}

pub(super) fn build_path_allow_plan(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    roots: &[AllowRoot],
    executable: &Path,
    abi: u32,
) -> Result<Plan, String> {
    let abi = require_abi(provider, admitted, Ok(abi))?;
    let storage = admitted.admits("storage");
    if storage && roots.is_empty() {
        return Err("provider start is refused: the path allow-list has no file roots".to_string());
    }
    let mut rules = Vec::with_capacity(roots.len() + 4);
    let mut root_dev = Vec::with_capacity(roots.len());
    let mut root_ino = Vec::with_capacity(roots.len());
    if storage {
        for root in roots {
            if !root.path.is_absolute() {
                return Err(format!(
                    "provider start is refused: {} is not an absolute Landlock root",
                    root.name
                ));
            }
            rules.push(PathRule(root.name, root.path.clone(), STORAGE));
            root_dev.push(root.dev);
            root_ino.push(root.ino);
        }
    }
    if admitted.admits("bound-executable") {
        if !executable.is_absolute() {
            return Err(
                "provider start is refused: the provider executable path is not absolute"
                    .to_string(),
            );
        }
        rules.push(PathRule(
            "PROVIDER_EXECUTABLE",
            executable.to_path_buf(),
            BINARY,
        ));
        for path in loader_paths(provider, LoaderArch::host()) {
            rules.push(PathRule("LANDLOCK_LOADER_PATHS", path.into(), BINARY));
        }
    }
    if matches!(provider, RuntimeProviderId::Chain) {
        for path in CHAIN_RESOLVER_FILES {
            // Follow the symlink for existence, and store the literal path.
            // The installer opens that literal with O_PATH, which lands on the target inode.
            if std::fs::metadata(path).is_ok() {
                rules.push(PathRule("READ_ONLY_FILE", (*path).into(), READ_FILE));
            }
        }
    }
    let storage_dev = root_dev.first().copied().unwrap_or(0);
    let storage_ino = root_ino.first().copied().unwrap_or(0);
    Ok(Plan {
        abi,
        handled: handled_fs(abi),
        rules,
        storage_dev,
        storage_ino,
        root_dev,
        root_ino,
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
            Localhost => "LOCALHOST_PROVIDER",
            Object => "OBJECT_PROVIDER",
            Chain => "CHAIN_PROVIDER",
        };
        if users.contains(name) {
            result.extend(paths(lab_section(
                &LAB[extra[index].0..],
                "const LIBM_LANDLOCK_LOADER_PATHS",
            )));
        }
        result
    }

    fn localhost_grant() -> super::super::rights::AdmittedRights {
        super::super::rights::admit_runtime_grant(Localhost)
    }

    #[test]
    fn abi_rows_name_the_kernel_and_narrow_the_handled_mask() {
        let admitted = localhost_grant();
        let exe = Path::new("/bin/localhost-provider");
        let root = || AllowRoot {
            name: "ElastOS",
            path: "/data/ElastOS".into(),
            dev: 1,
            ino: 2,
        };
        for abi in [1, 2] {
            let err = build_path_allow_plan(Localhost, &admitted, &[root()], exe, abi).unwrap_err();
            assert!(
                err.contains(&format!("this kernel reports Landlock ABI {abi}")),
                "{err}"
            );
            assert!(err.contains("truncate needs ABI 3"), "{err}");
        }
        assert_eq!(
            require_abi(Localhost, &admitted, Err(io::Error::other("query failed"))),
            Err("linux confinement refused: the kernel has no Landlock".to_string())
        );
        for (abi, mask) in [(3, 0x7fff_u64), (4, 0x7fff), (5, 0xffff), (6, 0xffff)] {
            let plan = build_path_allow_plan(Localhost, &admitted, &[root()], exe, abi).unwrap();
            assert_eq!(plan.abi, abi);
            assert_eq!(plan.handled, mask, "abi {abi}");
            assert_eq!(plan.handled, handled_fs(abi));
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(query_abi().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn ioctl_in_a_seccomp_list_requires_abi_5() {
        use super::super::seccomp_list::AuditArch;
        for provider in [Did, Wallet, Model, Localhost, Object, Chain] {
            let admitted = if matches!(provider, Did | Wallet | Model) {
                super::super::rights::admit_committed(provider)
            } else {
                super::super::rights::admit_runtime_grant(provider)
            };
            for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
                let names =
                    super::super::seccomp_list::linux_seccomp_list(provider, &admitted, arch);
                let needed = abi_required(&names);
                if names.contains(&"ioctl") {
                    assert!(
                        needed >= 5,
                        "{provider:?} {arch:?} admits ioctl and ABI {needed} does not cover it"
                    );
                } else {
                    assert_eq!(needed, 3, "{provider:?} {arch:?}");
                }
            }
        }
        assert_eq!(abi_required(&["openat", "ioctl"]), 5);
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
                Localhost => "localhost-provider",
                Object => "object-provider",
                Chain => "chain-provider",
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
                        let Some(mask) = masks.get(form).copied() else {
                            assert!(form.starts_with("(allow iokit-open") || form.starts_with("(allow mach-lookup") || form == r#"(allow file-read* (regex "^/System/Library/Extensions/AGXMetal[A-Za-z0-9_]+\\.bundle(/.*)?$"))"#, "lab form has no mask: {form}");
                            continue;
                        };
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

    #[test]
    fn chain_read_only_files_are_the_three_resolver_paths() {
        let root = AllowRoot {
            name: "chain-provider",
            path: "/data/chain-provider".into(),
            dev: 1,
            ino: 2,
        };
        let plan = build_path_allow_plan(
            Chain,
            &super::super::rights::admit_runtime_grant(Chain),
            &[root],
            Path::new("/bin/chain-provider"),
            5,
        )
        .unwrap();
        assert_eq!(plan.rules[0].0, "chain-provider");
        let files: Vec<_> = plan
            .rules
            .iter()
            .filter(|rule| rule.0 == "READ_ONLY_FILE")
            .collect();
        for rule in &files {
            let path = rule.1.to_str().unwrap();
            assert!(
                CHAIN_RESOLVER_FILES.contains(&path),
                "unexpected resolver file {path}"
            );
            assert_eq!(rule.2, READ_FILE);
            assert!(!path.contains("identity") && !path.contains("gai.conf"));
            assert!(!path.contains("host.conf") && !path.contains("ld.so"));
        }
        let local = AllowRoot {
            name: "ElastOS",
            path: "/data/ElastOS".into(),
            dev: 1,
            ino: 2,
        };
        let local_plan = build_path_allow_plan(
            Localhost,
            &super::super::rights::admit_runtime_grant(Localhost),
            &[local],
            Path::new("/bin/localhost-provider"),
            5,
        )
        .unwrap();
        assert!(local_plan
            .rules
            .iter()
            .all(|rule| rule.0 != "READ_ONLY_FILE"));
    }
}
