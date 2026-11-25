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
pub(super) const BINARY: u64 = 0x5;
/// `LANDLOCK_ACCESS_FS_READ_FILE` (1 << 2). A resolver file is not a storage root.
const READ_FILE: u64 = 4;
/// glibc NSS and the resolver. Optional files stay closed: the note measured
/// `/etc/gai.conf` and `/etc/host.conf` as nonfatal, and glibc 2.39 does not
/// open `ld.so.cache` or `libnss`.
const CHAIN_RESOLVER_FILES: &[&str] = &["/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"];
const NO_LANDLOCK: &str = "linux confinement refused: the kernel has no Landlock";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoaderArch {
    X86_64,
    Aarch64,
}

impl LoaderArch {
    pub(super) fn host() -> Self {
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

/// Inside uid of outside uid 0 on the identity map. Production Linux reads
/// `/proc/self/uid_map` and does not assume this constant. The row that plants
/// a file owned by this process compares that owner with this value.
const TRUSTED_LOADER_UID: u32 = 0;

/// Present when the file is a trusted regular file. A missing one is not a
/// refusal. An unsafe one is left out and named.
const OPTIONAL_LIBRARIES: &[&str] = &[
    "libm.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "libutil.so.1",
    "libanl.so.1",
];

fn static_loader_paths(provider: RuntimeProviderId, arch: LoaderArch) -> Vec<&'static str> {
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

fn loader_dirs(arch: LoaderArch) -> [&'static str; 6] {
    match arch {
        LoaderArch::X86_64 => [
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        ],
        LoaderArch::Aarch64 => [
            "/lib/aarch64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        ],
    }
}

fn loader_name(arch: LoaderArch) -> &'static str {
    match arch {
        LoaderArch::X86_64 => "ld-linux-x86-64.so.2",
        LoaderArch::Aarch64 => "ld-linux-aarch64.so.1",
    }
}

fn preferred_loader(arch: LoaderArch) -> &'static str {
    match arch {
        LoaderArch::X86_64 => "/lib64/ld-linux-x86-64.so.2",
        LoaderArch::Aarch64 => "/lib/ld-linux-aarch64.so.1",
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocatedFile {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub pinned: bool,
}

#[derive(Debug)]
pub(super) struct PlannedLoaders {
    pub files: Vec<LocatedFile>,
    pub omitted: Vec<String>,
}

#[cfg(test)]
thread_local! {
    static LOADER_FIXTURE: std::cell::RefCell<Option<(PathBuf, u32)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_loader_fixture(root: Option<(PathBuf, u32)>) {
    LOADER_FIXTURE.with(|slot| *slot.borrow_mut() = root);
}

/// The test fixture, when a row planted a loader tree. Production has none.
#[cfg(test)]
fn planned_from_loader_fixture(
    provider: RuntimeProviderId,
    arch: LoaderArch,
) -> Option<Result<PlannedLoaders, String>> {
    let (root, uid) = LOADER_FIXTURE.with(|slot| slot.borrow().clone())?;
    Some(resolve_loader_paths(provider, arch, &root, None, uid))
}

#[cfg(not(test))]
fn planned_from_loader_fixture(
    _provider: RuntimeProviderId,
    _arch: LoaderArch,
) -> Option<Result<PlannedLoaders, String>> {
    None
}

fn plan_loaders(provider: RuntimeProviderId, arch: LoaderArch) -> Result<PlannedLoaders, String> {
    // The host arch is the machine that will open the files. The other arch
    // stays the Debian row: one machine does not hold both sysroots. That
    // static row still carries the historical `libm` paths. The host arch
    // adds `libm` and the other optional libraries only when they are present
    // and trusted.
    // A musl build is still this Linux fence (`target_os = "linux"` and
    // x86_64 or aarch64). It does not have a second start. The names below
    // are the glibc loader and `libc.so.6`. Musl's `ld-musl-*.so.1` is not
    // one of them, so the start refuses by the glibc loader's name and the
    // directory list. The musl tree in `loader_paths_follow_the_fixed_directory_list`
    // pins that.
    if let Some(planned) = planned_from_loader_fixture(provider, arch) {
        return planned;
    }
    #[cfg(target_os = "linux")]
    if arch == LoaderArch::host() {
        let uid = trusted_loader_uid()?;
        return resolve_loader_paths(provider, arch, Path::new("/"), None, uid);
    }
    Ok(PlannedLoaders {
        files: static_loader_paths(provider, arch)
            .into_iter()
            .map(|path| LocatedFile {
                path: PathBuf::from(path),
                dev: 0,
                ino: 0,
                pinned: false,
            })
            .collect(),
        omitted: Vec::new(),
    })
}

/// Inside uid that maps to outside uid 0. No such range means the caller uses
/// the overflow uid. A map that cannot be read refuses the start.
#[cfg(target_os = "linux")]
fn trusted_loader_uid() -> Result<u32, String> {
    let text = std::fs::read_to_string("/proc/self/uid_map").map_err(|_| {
        "provider start is refused: the user namespace map cannot be read".to_string()
    })?;
    if let Some(uid) = uid_mapped_from_outside_root(&text) {
        return Ok(uid);
    }
    let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65534);
    Ok(overflow)
}

fn uid_mapped_from_outside_root(text: &str) -> Option<u32> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let inside: u32 = parts.next()?.parse().ok()?;
        let outside: u32 = parts.next()?.parse().ok()?;
        let count: u64 = parts.next()?.parse().ok()?;
        if outside == 0 && count > 0 {
            return Some(inside);
        }
    }
    None
}

/// First existing file in `directories`, or the fixed six when `directories`
/// is `None`. The dynamic loader tries its traditional path first, then the
/// same directories. The returned path is the path that existed. Owner, mode,
/// and device and inode come from the opened handle of the resolved file.
/// A parent writable by group or other refuses. The walk stops at `root`.
#[cfg(unix)]
pub(super) fn resolve_loader_paths(
    provider: RuntimeProviderId,
    arch: LoaderArch,
    root: &Path,
    directories: Option<&[&str]>,
    trust_uid: u32,
) -> Result<PlannedLoaders, String> {
    let _ = provider;
    let standard;
    let dirs: &[&str] = if let Some(dirs) = directories {
        dirs
    } else {
        standard = loader_dirs(arch);
        &standard
    };
    let mut files = Vec::new();
    let mut omitted = Vec::new();
    for name in [loader_name(arch), "libc.so.6", "libgcc_s.so.1"] {
        let preferred = (name == loader_name(arch)).then_some(preferred_loader(arch));
        match locate(root, dirs, name, preferred, trust_uid) {
            Ok(file) => files.push(file),
            Err(fail) => return Err(fail.message(name, dirs, preferred)),
        }
    }
    for name in OPTIONAL_LIBRARIES {
        match locate(root, dirs, name, None, trust_uid) {
            Ok(file) => files.push(file),
            Err(LocateFail::Missing) => {}
            Err(LocateFail::Refused { tried }) => {
                omitted.push(format!("provider start is refused: {name}, tried {tried}"))
            }
        }
    }
    Ok(PlannedLoaders { files, omitted })
}

#[cfg(unix)]
enum LocateFail {
    Missing,
    Refused { tried: String },
}

#[cfg(unix)]
fn locate(
    root: &Path,
    dirs: &[&str],
    name: &str,
    preferred: Option<&str>,
    trust_uid: u32,
) -> Result<LocatedFile, LocateFail> {
    let mut tried = Vec::new();
    if let Some(path) = preferred {
        tried.push(path.to_string());
    }
    for dir in dirs {
        let path = format!("{dir}/{name}");
        if !tried.contains(&path) {
            tried.push(path);
        }
    }
    let list = tried.join(", ");
    for rel in &tried {
        let candidate = under_root(root, rel);
        if std::fs::symlink_metadata(&candidate).is_err() {
            continue;
        }
        return match inspect_loader(&candidate, root, trust_uid) {
            Ok(file) => Ok(file),
            Err(()) => Err(LocateFail::Refused { tried: list }),
        };
    }
    Err(LocateFail::Missing)
}

#[cfg(unix)]
fn inspect_loader(candidate: &Path, root: &Path, trust_uid: u32) -> Result<LocatedFile, ()> {
    let info = open_loader_stat(candidate).map_err(|_| ())?;
    let regular = info.st_mode & libc::S_IFMT == libc::S_IFREG;
    let owner = info.st_uid as u32 == trust_uid;
    let private_file = info.st_mode & 0o022 == 0;
    if !regular || !owner || !private_file || !parents_are_private(root, candidate) {
        return Err(());
    }
    match std::fs::canonicalize(candidate) {
        Ok(canonical) if canonical != candidate && !parents_are_private(root, &canonical) => {
            Err(())
        }
        Ok(_) => {
            let (dev, ino) = loader_identity(&info);
            Ok(LocatedFile {
                path: candidate.to_path_buf(),
                dev,
                ino,
                pinned: true,
            })
        }
        Err(_) => Err(()),
    }
}

#[cfg(unix)]
fn open_loader_stat(path: &Path) -> std::io::Result<libc::stat> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul"))?;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDONLY | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(fd, info.as_mut_ptr()) };
    unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

#[cfg(unix)]
fn loader_identity(info: &libc::stat) -> (u64, u64) {
    #[cfg(target_os = "linux")]
    let dev = info.st_dev;
    #[cfg(not(target_os = "linux"))]
    let dev = info.st_dev as u64;
    (dev, info.st_ino)
}

/// Parents of `file` up to and including `root`. A group-writable or
/// other-writable directory refuses. The walk does not leave `root`, so a
/// world-writable temp parent is not this file's parent.
#[cfg(unix)]
fn parents_are_private(root: &Path, file: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let bounded = root != Path::new("/") && file.starts_with(root);
    let Some(parent) = file.parent() else {
        return true;
    };
    let mut current = parent.to_path_buf();
    loop {
        if bounded && current != root && !current.starts_with(root) {
            return true;
        }
        let Ok(meta) = std::fs::metadata(&current) else {
            return false;
        };
        if meta.mode() & 0o022 != 0 {
            return false;
        }
        if current == root || current == Path::new("/") {
            return true;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return true,
        }
    }
}

impl LocateFail {
    #[cfg(unix)]
    fn message(self, name: &str, dirs: &[&str], preferred: Option<&str>) -> String {
        let mut tried = Vec::new();
        if let Some(path) = preferred {
            tried.push(path.to_string());
        }
        for dir in dirs {
            let path = format!("{dir}/{name}");
            if !tried.contains(&path) {
                tried.push(path);
            }
        }
        let list = tried.join(", ");
        match self {
            LocateFail::Missing => {
                format!("provider start is refused: {name} was not in {list}")
            }
            LocateFail::Refused { tried } => {
                format!("provider start is refused: {name}, tried {tried}")
            }
        }
    }
}

#[cfg(unix)]
fn under_root(root: &Path, absolute: &str) -> PathBuf {
    let rel = absolute.trim_start_matches('/');
    if root == Path::new("/") {
        PathBuf::from(format!("/{rel}"))
    } else {
        root.join(rel)
    }
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
    /// Device and inode of a file rule opened at plan time, in rule order.
    /// `None` is a directory root or a path this machine did not open.
    pub file_pins: Vec<Option<(u64, u64)>>,
    /// Optional libraries that existed and were left out because they were
    /// not a trusted regular file. A missing optional library is not here.
    pub omitted_libraries: Vec<String>,
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
/// on the storage list, so refer is not subtracted. A declared `ioctl` selects
/// ABI 5. The filter does not admit that name when it has no number row.
pub(super) fn abi_required(names: &[&str]) -> u32 {
    if names.contains(&"ioctl") {
        5
    } else if STORAGE & (1 << 14) != 0 {
        3
    } else {
        2
    }
}

pub(super) fn require_abi(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    reported: io::Result<u32>,
) -> Result<u32, String> {
    let needed = abi_required(&super::seccomp_list::declared_linux_names(
        provider, admitted,
    ));
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

/// `NoNewPrivs: 1` and `Seccomp: 2` (filter mode) are the confined child.
/// Anything else is a refusal the parent names.
pub(super) fn child_confinement_refusal(status: &str) -> Option<&'static str> {
    let mut no_new_privs = false;
    let mut seccomp_filter = false;
    for line in status.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("NoNewPrivs:"), Some("1")) => no_new_privs = true,
            (Some("Seccomp:"), Some("2")) => seccomp_filter = true,
            _ => {}
        }
    }
    if no_new_privs && seccomp_filter {
        None
    } else {
        Some("provider start is refused: the child is not confined (NoNewPrivs and Seccomp)")
    }
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
    let mut file_pins = Vec::new();
    // Path rules come from the admitted rows. Loader paths stay with the provider.
    for row in admitted.rows() {
        for form in row.rules {
            match *form {
                r#"(allow file-read* (literal (param "STORAGE_PARENT")))"# => {}
                r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"# => {
                    rules.push(PathRule(
                        "STORAGE_ROOT",
                        bindings.storage_root.clone(),
                        STORAGE,
                    ));
                    file_pins.push(None);
                }
                r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"# => {
                    rules.push(PathRule(
                        "PROVIDER_EXECUTABLE",
                        bindings.provider_executable.clone(),
                        BINARY,
                    ));
                    file_pins.push(None);
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
    let planned = plan_loaders(provider, arch)?;
    for file in planned.files {
        let pin = file.pinned.then_some((file.dev, file.ino));
        rules.push(PathRule("LANDLOCK_LOADER_PATHS", file.path, BINARY));
        file_pins.push(pin);
    }
    Ok(Plan {
        abi,
        handled: handled_fs(abi),
        rules,
        storage_dev: bindings.storage_dev,
        storage_ino: bindings.storage_ino,
        root_dev: Vec::new(),
        root_ino: Vec::new(),
        file_pins,
        omitted_libraries: planned.omitted,
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
    let mut file_pins = Vec::with_capacity(roots.len() + 4);
    let mut root_dev = Vec::with_capacity(roots.len());
    let mut root_ino = Vec::with_capacity(roots.len());
    let mut omitted_libraries = Vec::new();
    if storage {
        for root in roots {
            if !root.path.is_absolute() {
                return Err(format!(
                    "provider start is refused: {} is not an absolute Landlock root",
                    root.name
                ));
            }
            rules.push(PathRule(root.name, root.path.clone(), STORAGE));
            file_pins.push(None);
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
        file_pins.push(None);
        let planned = plan_loaders(provider, LoaderArch::host())?;
        for file in planned.files {
            let pin = file.pinned.then_some((file.dev, file.ino));
            rules.push(PathRule("LANDLOCK_LOADER_PATHS", file.path, BINARY));
            file_pins.push(pin);
        }
        omitted_libraries = planned.omitted;
    }
    if matches!(provider, RuntimeProviderId::Chain) {
        for path in CHAIN_RESOLVER_FILES {
            // Follow the symlink for existence, and store the literal path.
            // The installer opens that literal with O_PATH, which lands on the target inode.
            if std::fs::metadata(path).is_ok() {
                rules.push(PathRule("READ_ONLY_FILE", (*path).into(), READ_FILE));
                file_pins.push(None);
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
        file_pins,
        omitted_libraries,
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
            let declared = super::super::seccomp_list::declared_linux_names(provider, &admitted);
            assert!(!declared.contains(&"ioctl"), "{provider:?} declares ioctl");
            let mut with_ioctl = declared.clone();
            with_ioctl.push("ioctl");
            assert_eq!(
                abi_required(&with_ioctl),
                5,
                "{provider:?} declared ioctl does not select ABI 5"
            );
            for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
                let names =
                    super::super::seccomp_list::linux_seccomp_list(provider, &admitted, arch);
                assert!(
                    !names.contains(&"ioctl"),
                    "{provider:?} {arch:?} admits an unlisted ioctl"
                );
                assert_eq!(abi_required(&names), 3, "{provider:?} {arch:?}");
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
                let host = std::mem::discriminant(&arch) == std::mem::discriminant(&LoaderArch::host());
                let resolves = cfg!(target_os = "linux") && host;
                let multiarch = match arch {
                    LoaderArch::X86_64 => "/lib/x86_64-linux-gnu/libc.so.6",
                    LoaderArch::Aarch64 => "/lib/aarch64-linux-gnu/libc.so.6",
                };
                // Fedora, Arch, and musl do not have the Debian multiarch file.
                // Comparing those plans with the Debian strings is red for the
                // wrong reason. A Debian host may also map optional libraries.
                let debian_family = std::fs::metadata(multiarch).is_ok();
                let got_paths: Vec<_> = plan.rules.iter().map(|rule| (rule.0, rule.1.clone())).collect();
                let expect_paths: Vec<_> = expected.iter().map(|rule| (rule.0, rule.1.clone())).collect();
                if resolves && !debian_family {
                    assert!(plan.rules.iter().any(|rule| rule.0 == "LANDLOCK_LOADER_PATHS"), "{name}");
                } else if resolves {
                    assert!(expect_paths.iter().all(|rule| got_paths.contains(rule)), "{name} {arch:?} lost a Debian row");
                    for rule in &got_paths {
                        if !expect_paths.contains(rule) {
                            let file = rule.1.file_name().and_then(|name| name.to_str()).unwrap_or("");
                            assert!(OPTIONAL_LIBRARIES.contains(&file), "{name} unexpected {file}");
                        }
                    }
                } else {
                    assert_eq!(got_paths, expect_paths, "{name} {arch:?} paths");
                }
                if got_paths.len() == expect_paths.len() {
                    assert_eq!(plan.rules.iter().map(|rule| (rule.0, rule.2)).collect::<Vec<_>>(), expected.iter().map(|rule| (rule.0, rule.2)).collect::<Vec<_>>(), "{name} {arch:?} masks");
                }
                assert_eq!(plan.handled, handled, "{name} {arch:?} handled");
                assert_eq!(plan.file_pins.len(), plan.rules.len());
                if host && !resolves {
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

    #[cfg(unix)]
    fn plant(root: &std::path::Path, rel: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = under_root(root, rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"library").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    fn resolved_paths(
        provider: RuntimeProviderId,
        arch: LoaderArch,
        root: &Path,
        directories: Option<&[&str]>,
        trust_uid: u32,
    ) -> Result<Vec<PathBuf>, String> {
        resolve_loader_paths(provider, arch, root, directories, trust_uid)
            .map(|planned| planned.files.into_iter().map(|file| file.path).collect())
    }

    #[cfg(unix)]
    fn names_for(provider: RuntimeProviderId, arch: LoaderArch) -> Vec<&'static str> {
        static_loader_paths(provider, arch)
            .into_iter()
            .map(|path| path.rsplit('/').next().unwrap())
            .collect()
    }

    /// Debian's resolved paths are today's row when only those files exist.
    /// Fedora and Arch take the first later directory. busybox:glibc keeps
    /// glibc (`libc.so.6`) in `/lib`. Musl's names are a different tree and
    /// are refused. A missing library names the list. A group-writable file,
    /// a user-owned file, a bad symlink target, and a parent writable by
    /// others are refused by the library name and the list. The rule is that
    /// one file.
    #[cfg(unix)]
    #[test]
    fn loader_paths_follow_the_fixed_directory_list() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use RuntimeProviderId::*;
        let uid = unsafe { libc::geteuid() };
        assert_eq!(TRUSTED_LOADER_UID, 0);
        let providers = [Did, Wallet, Model, Localhost, Object, Chain];
        for arch in [LoaderArch::X86_64, LoaderArch::Aarch64] {
            for provider in providers {
                let debian = tempfile::tempdir().unwrap();
                for path in static_loader_paths(provider, arch) {
                    plant(debian.path(), path, 0o755);
                }
                // The real Debian loader also sits in the multiarch directory.
                // The traditional path stays the row.
                plant(
                    debian.path(),
                    &format!(
                        "/lib/{}/{}",
                        match arch {
                            LoaderArch::X86_64 => "x86_64-linux-gnu",
                            LoaderArch::Aarch64 => "aarch64-linux-gnu",
                        },
                        loader_name(arch)
                    ),
                    0o755,
                );
                let got = resolved_paths(provider, arch, debian.path(), None, uid).unwrap();
                let expect: Vec<_> = static_loader_paths(provider, arch)
                    .into_iter()
                    .map(|path| under_root(debian.path(), path))
                    .collect();
                assert_eq!(got, expect, "{provider:?} {arch:?} left today's row");
                assert!(got.iter().all(|path| path.is_file()), "{got:?}");
            }
        }

        let fedora = tempfile::tempdir().unwrap();
        for name in names_for(Model, LoaderArch::X86_64) {
            plant(fedora.path(), &format!("/lib64/{name}"), 0o755);
        }
        let got = resolved_paths(Model, LoaderArch::X86_64, fedora.path(), None, uid).unwrap();
        assert!(
            got.iter()
                .all(|path| path.starts_with(fedora.path().join("lib64"))),
            "{got:?}"
        );

        let arch_root = tempfile::tempdir().unwrap();
        for name in names_for(Chain, LoaderArch::X86_64) {
            plant(arch_root.path(), &format!("/usr/lib64/{name}"), 0o755);
        }
        let got = resolved_paths(Chain, LoaderArch::X86_64, arch_root.path(), None, uid).unwrap();
        assert!(
            got.iter()
                .all(|path| path.starts_with(arch_root.path().join("usr/lib64"))),
            "{got:?}"
        );

        for (arch, loader) in [
            (LoaderArch::X86_64, "ld-linux-x86-64.so.2"),
            (LoaderArch::Aarch64, "ld-linux-aarch64.so.1"),
        ] {
            let busy = tempfile::tempdir().unwrap();
            for provider in providers {
                for name in names_for(provider, arch) {
                    plant(busy.path(), &format!("/lib/{name}"), 0o755);
                }
            }
            let got = resolved_paths(Localhost, arch, busy.path(), None, uid).unwrap();
            assert_eq!(got[0], under_root(busy.path(), &format!("/lib/{loader}")));
            assert!(
                got.iter()
                    .all(|path| !path.to_string_lossy().contains("linux-gnu")),
                "{got:?}"
            );
        }

        // Musl's loader and libc names are not the glibc names this fence
        // opens. A musl-targeted build still runs this Linux start, and the
        // start refuses by the glibc loader name and the six directories.
        for (arch, musl_loader, glibc_loader) in [
            (
                LoaderArch::X86_64,
                "ld-musl-x86_64.so.1",
                "ld-linux-x86-64.so.2",
            ),
            (
                LoaderArch::Aarch64,
                "ld-musl-aarch64.so.1",
                "ld-linux-aarch64.so.1",
            ),
        ] {
            let musl = tempfile::tempdir().unwrap();
            plant(musl.path(), &format!("/lib/{musl_loader}"), 0o755);
            plant(musl.path(), "/lib/libc.so", 0o755);
            let err = resolve_loader_paths(Localhost, arch, musl.path(), None, uid).unwrap_err();
            assert!(
                err.starts_with(&format!(
                    "provider start is refused: {glibc_loader} was not in "
                )),
                "{err}"
            );
            for dir in loader_dirs(arch) {
                assert!(err.contains(dir), "{err}");
            }
            assert!(!err.contains(musl_loader), "{err}");
            assert!(!err.contains("libc.so "), "{err}");
        }

        let missing = tempfile::tempdir().unwrap();
        let err = resolve_loader_paths(Localhost, LoaderArch::X86_64, missing.path(), None, uid)
            .unwrap_err();
        assert!(
            err.starts_with("provider start is refused: ld-linux-x86-64.so.2 was not in "),
            "{err}"
        );
        for dir in loader_dirs(LoaderArch::X86_64) {
            assert!(err.contains(dir), "{err}");
        }
        let beside = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            if !path.ends_with("libc.so.6") {
                plant(beside.path(), path, 0o755);
            }
        }
        plant(beside.path(), "/opt/chain-provider/libc.so.6", 0o755);
        let err = resolve_loader_paths(Localhost, LoaderArch::X86_64, beside.path(), None, uid)
            .unwrap_err();
        assert!(err.contains("libc.so.6 was not in "), "{err}");
        assert!(!err.contains("/opt"), "{err}");

        let loose = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            plant(
                loose.path(),
                path,
                if path.ends_with("libc.so.6") {
                    0o664
                } else {
                    0o755
                },
            );
        }
        let err = resolve_loader_paths(Localhost, LoaderArch::X86_64, loose.path(), None, uid)
            .unwrap_err();
        assert!(
            err.starts_with("provider start is refused: libc.so.6, tried "),
            "{err}"
        );
        for dir in loader_dirs(LoaderArch::X86_64) {
            assert!(err.contains(dir), "{err}");
        }

        // A planted file is owned by this process. The root-owner row runs
        // when this process is not root, which is the only uid this row can plant.
        if uid != TRUSTED_LOADER_UID {
            let owned = tempfile::tempdir().unwrap();
            for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
                plant(owned.path(), path, 0o755);
            }
            let err = resolve_loader_paths(
                Localhost,
                LoaderArch::X86_64,
                owned.path(),
                None,
                TRUSTED_LOADER_UID,
            )
            .unwrap_err();
            assert!(
                err.starts_with("provider start is refused: ld-linux-x86-64.so.2, tried "),
                "{err}"
            );
            for dir in loader_dirs(LoaderArch::X86_64) {
                assert!(err.contains(dir), "{err}");
            }
        }
        let directory = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            if path.ends_with("libc.so.6") {
                let dir = under_root(directory.path(), path);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            } else {
                plant(directory.path(), path, 0o755);
            }
        }
        let err = resolve_loader_paths(Localhost, LoaderArch::X86_64, directory.path(), None, uid)
            .unwrap_err();
        assert!(
            err.starts_with("provider start is refused: libc.so.6, tried "),
            "{err}"
        );
        for dir in loader_dirs(LoaderArch::X86_64) {
            assert!(err.contains(dir), "{err}");
        }

        let linked = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            if path.ends_with("libc.so.6") {
                let final_file = plant(linked.path(), "/final/libc.so.6", 0o755);
                let mid = under_root(linked.path(), "/lib/x86_64-linux-gnu/mid");
                std::fs::create_dir_all(mid.parent().unwrap()).unwrap();
                symlink(&final_file, &mid).unwrap();
                symlink("mid", under_root(linked.path(), path)).unwrap();
            } else {
                plant(linked.path(), path, 0o755);
            }
        }
        let got = resolved_paths(Localhost, LoaderArch::X86_64, linked.path(), None, uid).unwrap();
        let libc = under_root(linked.path(), "/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(
            got.iter().find(|path| path.ends_with("libc.so.6")),
            Some(&libc)
        );
        assert_ne!(std::fs::canonicalize(&libc).unwrap(), libc);
        std::fs::set_permissions(
            under_root(linked.path(), "/final/libc.so.6"),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let err = resolve_loader_paths(Localhost, LoaderArch::X86_64, linked.path(), None, uid)
            .unwrap_err();
        assert!(
            err.starts_with("provider start is refused: libc.so.6, tried "),
            "{err}"
        );
        for dir in loader_dirs(LoaderArch::X86_64) {
            assert!(err.contains(dir), "{err}");
        }

        // A parent other people can write is not a trusted directory.
        let open_parent = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            plant(open_parent.path(), path, 0o755);
        }
        let loose_dir = under_root(open_parent.path(), "/lib/x86_64-linux-gnu");
        std::fs::set_permissions(&loose_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err =
            resolve_loader_paths(Localhost, LoaderArch::X86_64, open_parent.path(), None, uid)
                .unwrap_err();
        assert!(
            err.starts_with("provider start is refused: libc.so.6, tried "),
            "{err}"
        );

        // /lib64 is a symlink to usr/lib64 on Debian. The stored path stays
        // the link. The owner check is the resolved file.
        let lib64 = tempfile::tempdir().unwrap();
        for path in static_loader_paths(Localhost, LoaderArch::X86_64) {
            let name = path.rsplit('/').next().unwrap();
            plant(lib64.path(), &format!("/usr/lib64/{name}"), 0o755);
        }
        std::fs::create_dir_all(under_root(lib64.path(), "/usr")).unwrap();
        symlink("usr/lib64", under_root(lib64.path(), "/lib64")).unwrap();
        let planned =
            resolve_loader_paths(Localhost, LoaderArch::X86_64, lib64.path(), None, uid).unwrap();
        assert!(planned.files.iter().all(|file| {
            file.pinned
                && file.path.to_string_lossy().contains("/lib64/")
                && !file.path.to_string_lossy().contains("usr/lib64")
        }));
        assert!(std::fs::canonicalize(&planned.files[0].path)
            .unwrap()
            .to_string_lossy()
            .contains("usr/lib64"));
    }

    #[cfg(unix)]
    #[test]
    fn every_provider_maps_optional_libraries_when_they_are_trusted() {
        use std::os::unix::fs::PermissionsExt;
        use RuntimeProviderId::*;
        let uid = unsafe { libc::geteuid() };
        let providers = [Did, Wallet, Model, Localhost, Object, Chain];
        let optional = [
            "libm.so.6",
            "libpthread.so.0",
            "libdl.so.2",
            "libutil.so.1",
            "libanl.so.1",
        ];
        for arch in [LoaderArch::X86_64, LoaderArch::Aarch64] {
            let required = [loader_name(arch), "libc.so.6", "libgcc_s.so.1"];
            for (label, dir) in [
                (
                    "debian",
                    format!(
                        "/lib/{}",
                        match arch {
                            LoaderArch::X86_64 => "x86_64-linux-gnu",
                            LoaderArch::Aarch64 => "aarch64-linux-gnu",
                        }
                    ),
                ),
                ("lib64", "/lib64".to_string()),
                ("lib", "/lib".to_string()),
            ] {
                let root = tempfile::tempdir().unwrap();
                for name in required.iter().chain(optional.iter()) {
                    plant(root.path(), &format!("{dir}/{name}"), 0o755);
                }
                for provider in providers {
                    let planned =
                        resolve_loader_paths(provider, arch, root.path(), None, uid).unwrap();
                    let names: Vec<_> = planned
                        .files
                        .iter()
                        .map(|file| {
                            file.path
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .into_owned()
                        })
                        .collect();
                    let expect: Vec<_> = required
                        .iter()
                        .chain(optional.iter())
                        .map(|name| (*name).to_string())
                        .collect();
                    assert_eq!(names, expect, "{provider:?} {arch:?} {label}");
                    assert!(planned.omitted.is_empty(), "{provider:?} {label}");
                    assert!(planned.files.iter().all(|file| {
                        file.pinned
                            && file
                                .path
                                .starts_with(root.path().join(dir.trim_start_matches('/')))
                    }));
                }
            }
        }
        let unsafe_root = tempfile::tempdir().unwrap();
        for name in ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"] {
            plant(unsafe_root.path(), &format!("/lib/{name}"), 0o755);
        }
        let loose = plant(unsafe_root.path(), "/lib/libm.so.6", 0o666);
        assert_eq!(
            std::fs::symlink_metadata(&loose)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o666
        );
        let planned =
            resolve_loader_paths(Localhost, LoaderArch::X86_64, unsafe_root.path(), None, uid)
                .unwrap();
        assert!(planned
            .files
            .iter()
            .all(|file| !file.path.ends_with("libm.so.6")));
        assert!(
            planned
                .omitted
                .iter()
                .any(|line| line.contains("libm.so.6")),
            "{:?}",
            planned.omitted
        );
        assert!(planned
            .omitted
            .iter()
            .all(|line| !line.contains("libanl.so.1")));
    }

    #[cfg(unix)]
    #[test]
    fn both_builders_use_the_resolved_loader_not_the_static_list() {
        use RuntimeProviderId::*;
        let root = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let arch = LoaderArch::host();
        for name in [loader_name(arch), "libc.so.6", "libgcc_s.so.1"] {
            plant(root.path(), &format!("/lib/{name}"), 0o755);
        }
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                set_loader_fixture(None);
            }
        }
        let _clear = Clear;
        set_loader_fixture(Some((root.path().to_path_buf(), uid)));
        let bindings = Bindings {
            storage_root: root.path().join("data"),
            provider_executable: root.path().join("localhost-provider"),
            storage_dev: 1,
            storage_ino: 2,
        };
        std::fs::create_dir_all(&bindings.storage_root).unwrap();
        std::fs::write(&bindings.provider_executable, b"bin").unwrap();
        let admitted = super::super::rights::admit_runtime_grant(Localhost);
        let plan = build(Localhost, &admitted, &bindings, 5).unwrap();
        let loaders: Vec<_> = plan
            .rules
            .iter()
            .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
            .map(|rule| rule.1.clone())
            .collect();
        assert!(!loaders.is_empty());
        assert!(
            loaders
                .iter()
                .all(|path| path.starts_with(root.path().join("lib"))
                    && !path.to_string_lossy().contains("linux-gnu")),
            "{loaders:?}"
        );
        let allow = build_path_allow_plan(
            Localhost,
            &admitted,
            &[AllowRoot {
                name: "data",
                path: bindings.storage_root.clone(),
                dev: 1,
                ino: 2,
            }],
            &bindings.provider_executable,
            5,
        )
        .unwrap();
        let allow_loaders: Vec<_> = allow
            .rules
            .iter()
            .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
            .map(|rule| rule.1.clone())
            .collect();
        assert_eq!(allow_loaders, loaders);
        for (rule, pin) in plan.rules.iter().zip(plan.file_pins.iter()) {
            if rule.0 == "LANDLOCK_LOADER_PATHS" {
                assert!(pin.is_some(), "{}", rule.1.display());
            }
        }
    }

    #[test]
    fn the_identity_map_trusts_outside_root_and_a_shifted_map_does_not() {
        assert_eq!(uid_mapped_from_outside_root("0 0 4294967295\n"), Some(0));
        assert_eq!(uid_mapped_from_outside_root("1000 0 1\n"), Some(1000));
        assert_eq!(uid_mapped_from_outside_root("0 1000 1\n"), None);
        assert_eq!(uid_mapped_from_outside_root("0 0 0\n"), None);
        assert_eq!(
            uid_mapped_from_outside_root("65534 65534 1\n0 0 1\n"),
            Some(0)
        );
    }

    #[test]
    fn a_child_without_nonewprivs_and_seccomp_is_refused_by_name() {
        assert!(super::child_confinement_refusal("NoNewPrivs:\t0\nSeccomp:\t0\n").is_some());
        assert!(super::child_confinement_refusal("NoNewPrivs:\t1\nSeccomp:\t0\n").is_some());
        assert!(super::child_confinement_refusal("NoNewPrivs:\t1\nSeccomp:\t1\n").is_some());
        assert!(super::child_confinement_refusal("NoNewPrivs:\t1\nSeccomp:\t2\n").is_none());
        let reason = super::child_confinement_refusal("").unwrap();
        assert!(reason.contains("NoNewPrivs"), "{reason}");
        assert!(reason.contains("Seccomp"), "{reason}");
        let source = include_str!("failure_record.rs");
        let launch = source.split("fn launch(").nth(1).unwrap();
        let accept = launch.split("return Ok(pid)").next().unwrap();
        assert!(
            accept.contains("child_confinement_refusal"),
            "the parent accepts a child only after NoNewPrivs and Seccomp"
        );
    }

    #[test]
    fn the_installer_checks_the_planned_file_identity() {
        let source = include_str!("preexec_installer.rs");
        let install = source.split("unsafe fn install(").nth(1).unwrap();
        let body = install.split("\n#[cfg(test)]").next().unwrap();
        assert!(
            body.contains("open_pinned_regular_file"),
            "the child must open the planned file, not a swapped path"
        );
    }
}
