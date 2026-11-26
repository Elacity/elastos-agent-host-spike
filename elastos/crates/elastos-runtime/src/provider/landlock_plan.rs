//! Landlock file decisions for one provider launch; attachment comes later.
//!
//! Helpers only Linux (and its tests) call are gated. An omitted library is
//! named when the helper exits before it answers.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use elastos_common::elf_needed::{dt_needed, library_required, ph_at};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
#[cfg(test)]
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
#[derive(Debug)]
pub(super) struct LocatedFile {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub pinned: bool,
    /// Open from the check until the rule is added. A held file's inode
    /// cannot be reused by a path swapped in at the same name.
    pub held: Option<OwnedFd>,
}

/// What `PT_INTERP` on the already opened executable says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Interpreter {
    /// No `PT_INTERP`. A static program maps no loader and no library.
    Static,
    /// The host glibc loader (`ld-linux-*.so`).
    Glibc,
    /// The host musl loader (`ld-musl-*.so.1`), and only that name.
    Musl,
}

thread_local! {
    static INTERPRETER_FD: std::cell::Cell<i32> = const { std::cell::Cell::new(-1) };
    static CHECKED_DIRECTORY: std::cell::RefCell<Option<OwnedFd>> = const { std::cell::RefCell::new(None) };
    static LAST_OMITTED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn remember_omitted(omitted: &[String]) {
    LAST_OMITTED.with(|slot| *slot.borrow_mut() = omitted.to_vec());
}

/// Optional libraries the last plan left out. The bridge names them when the
/// helper exits before it answers.
#[cfg(target_os = "linux")]
pub(super) fn take_omitted_libraries() -> Vec<String> {
    LAST_OMITTED.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

/// Read `PT_INTERP` from this descriptor while `body` plans the loaders.
#[cfg(any(target_os = "linux", test))]
pub(super) fn with_interpreter_fd<T>(fd: i32, body: impl FnOnce() -> T) -> T {
    INTERPRETER_FD.with(|slot| {
        let previous = slot.replace(fd);
        let result = body();
        slot.set(previous);
        result
    })
}

/// The directory opened at the check. `build` takes it for `STORAGE_ROOT`.
#[cfg(target_os = "linux")]
pub(super) fn set_checked_directory(directory: OwnedFd) {
    CHECKED_DIRECTORY.with(|slot| *slot.borrow_mut() = Some(directory));
}

#[cfg(target_os = "linux")]
pub(super) fn clear_checked_directory() {
    CHECKED_DIRECTORY.with(|slot| drop(slot.borrow_mut().take()));
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn checked_directory_is_held() -> bool {
    CHECKED_DIRECTORY.with(|slot| slot.borrow().is_some())
}

#[cfg(any(target_os = "linux", test))]
fn take_checked_directory() -> Option<OwnedFd> {
    CHECKED_DIRECTORY.with(|slot| slot.borrow_mut().take())
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
    let interp = planned_interpreter().unwrap_or(Interpreter::Glibc);
    Some(resolve_named(provider, arch, &root, None, uid, interp))
}

#[cfg(not(test))]
fn planned_from_loader_fixture(
    _provider: RuntimeProviderId,
    _arch: LoaderArch,
) -> Option<Result<PlannedLoaders, String>> {
    None
}

fn musl_loader_name(arch: LoaderArch) -> &'static str {
    match arch {
        LoaderArch::X86_64 => "ld-musl-x86_64.so.1",
        LoaderArch::Aarch64 => "ld-musl-aarch64.so.1",
    }
}

fn planned_interpreter() -> Result<Interpreter, String> {
    let fd = INTERPRETER_FD.with(|slot| slot.get());
    if fd < 0 {
        return Ok(Interpreter::Glibc);
    }
    interpreter_of(fd)
}

/// `PT_INTERP` from an executable that is already open. No program header
/// means a static ELF: no loader row and no library row. A glibc or musl
/// basename for this architecture selects that loader. Any other interpreter
/// is refused by the path it names.
pub(super) fn interpreter_of(fd: i32) -> Result<Interpreter, String> {
    let mut header = [0u8; 64];
    pread_all(fd, &mut header, 0)?;
    if header[0..4] != [0x7f, b'E', b'L', b'F'] || header[4] != 2 || header[5] != 1 {
        return Err(
            "provider start is refused: the executable is not a 64-bit little-endian ELF"
                .to_string(),
        );
    }
    let phoff = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let phentsize = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let phnum = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if phnum == 0 {
        return Ok(Interpreter::Static);
    }
    if phentsize < 56 || phnum > 128 {
        return Err(elastos_common::elf_needed::UNUSABLE_PROGRAM_HEADERS.to_string());
    }
    for index in 0..phnum {
        let mut program = [0u8; 56];
        pread_all(fd, &mut program, ph_at(phoff, index, phentsize)?)?;
        let kind = u32::from_le_bytes(program[0..4].try_into().unwrap());
        if kind != 3 {
            continue;
        }
        let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let size = u64::from_le_bytes(program[32..40].try_into().unwrap()) as usize;
        if size == 0 || size > 4096 {
            return Err(
                "provider start is refused: the executable interpreter path is invalid".to_string(),
            );
        }
        let mut bytes = vec![0u8; size];
        pread_all(fd, &mut bytes, offset)?;
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        let path = String::from_utf8(bytes).map_err(|_| {
            "provider start is refused: the executable interpreter path is not utf-8".to_string()
        })?;
        return classify_interpreter(&path);
    }
    Ok(Interpreter::Static)
}

fn classify_interpreter(path: &str) -> Result<Interpreter, String> {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base == loader_name(LoaderArch::host()) {
        return Ok(Interpreter::Glibc);
    }
    if base == musl_loader_name(LoaderArch::host()) {
        return Ok(Interpreter::Musl);
    }
    Err(format!("provider start is refused: interpreter {path}"))
}

fn pread_all(fd: i32, buf: &mut [u8], offset: u64) -> Result<(), String> {
    let mut got = 0usize;
    while got < buf.len() {
        let read = unsafe {
            libc::pread(
                fd,
                buf[got..].as_mut_ptr().cast(),
                buf.len() - got,
                offset.saturating_add(got as u64) as i64,
            )
        };
        if read < 0 {
            return Err(format!(
                "provider start is refused: the executable could not be read: {}",
                io::Error::last_os_error()
            ));
        }
        if read == 0 {
            return Err(
                "provider start is refused: the executable is not a 64-bit little-endian ELF"
                    .to_string(),
            );
        }
        got += read as usize;
    }
    Ok(())
}

fn program_needed() -> Result<Option<Vec<String>>, String> {
    let fd = INTERPRETER_FD.with(|slot| slot.get());
    if fd < 0 {
        return Ok(None);
    }
    dt_needed(|buf, off| pread_all(fd, buf, off).is_ok(), "the executable").map(Some)
}

fn plan_loaders(provider: RuntimeProviderId, arch: LoaderArch) -> Result<PlannedLoaders, String> {
    // The host arch is the machine that will open the files. The other arch
    // stays the Debian row: one machine does not hold both sysroots. That
    // static row still carries the historical `libm` paths. The host arch
    // adds `libm` and the other optional libraries only when they are present
    // and trusted.
    // A static ELF has no `PT_INTERP`, so it maps no loader and no library.
    // `ld-musl-*.so.1` is resolved only when the interpreter names it, from
    // the same fixed directory list. Anything else is refused by that name.
    let interp = planned_interpreter()?;
    if let Some(planned) = planned_from_loader_fixture(provider, arch) {
        return planned;
    }
    if interp == Interpreter::Static {
        return Ok(PlannedLoaders {
            files: Vec::new(),
            omitted: Vec::new(),
        });
    }
    #[cfg(target_os = "linux")]
    if arch == LoaderArch::host() {
        let uid = trusted_loader_uid()?;
        return resolve_named(provider, arch, Path::new("/"), None, uid, interp);
    }
    if arch == LoaderArch::host() && interp == Interpreter::Musl {
        let uid = unsafe { libc::geteuid() };
        return resolve_named(provider, arch, Path::new("/"), None, uid, interp);
    }
    Ok(PlannedLoaders {
        files: static_loader_paths(provider, arch)
            .into_iter()
            .map(|path| LocatedFile {
                path: PathBuf::from(path),
                dev: 0,
                ino: 0,
                pinned: false,
                held: None,
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

#[cfg(any(target_os = "linux", test))]
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
#[cfg(all(unix, test))]
pub(super) fn resolve_loader_paths(
    provider: RuntimeProviderId,
    arch: LoaderArch,
    root: &Path,
    directories: Option<&[&str]>,
    trust_uid: u32,
) -> Result<PlannedLoaders, String> {
    resolve_named(
        provider,
        arch,
        root,
        directories,
        trust_uid,
        Interpreter::Glibc,
    )
}

/// A listed glibc library is required when the executable's own `DT_NEEDED`
/// names it. The loader is always required. A required library's own
/// `DT_NEEDED` is not walked: the dynamic linker already refuses a missing
/// soname of a library it has loaded, and reading those files is a second
/// parser on this path. Anything else in the list is optional and is allowed
/// only when the file is there. With no program descriptor the historical
/// `libc` and `libgcc` stay required.
fn glibc_libraries(
    arch: LoaderArch,
    root: &Path,
    dirs: &[&str],
    trust_uid: u32,
) -> Result<PlannedLoaders, String> {
    let needed = program_needed()?;
    let mut names = vec![loader_name(arch), "libc.so.6", "libgcc_s.so.1"];
    names.extend(OPTIONAL_LIBRARIES.iter().copied());
    let (mut files, mut omitted) = (Vec::new(), Vec::new());
    for name in names {
        let required = library_required(name, loader_name(arch), needed.as_deref());
        let preferred = (name == loader_name(arch)).then_some(preferred_loader(arch));
        match locate(root, dirs, name, preferred, trust_uid) {
            Ok(file) => files.push(file),
            Err(LocateFail::Missing) if !required => {}
            Err(LocateFail::Refused { tried }) if !required => {
                omitted.push(format!("omitted library {name}, tried {tried}"));
            }
            Err(fail) => return Err(fail.message(name, dirs, preferred)),
        }
    }
    Ok(PlannedLoaders { files, omitted })
}

fn resolve_named(
    provider: RuntimeProviderId,
    arch: LoaderArch,
    root: &Path,
    directories: Option<&[&str]>,
    trust_uid: u32,
    interp: Interpreter,
) -> Result<PlannedLoaders, String> {
    let _ = provider;
    if interp == Interpreter::Static {
        return Ok(PlannedLoaders {
            files: Vec::new(),
            omitted: Vec::new(),
        });
    }
    let standard;
    let dirs: &[&str] = if let Some(dirs) = directories {
        dirs
    } else {
        standard = loader_dirs(arch);
        &standard
    };
    if interp == Interpreter::Glibc {
        return glibc_libraries(arch, root, dirs, trust_uid);
    }
    let required = [musl_loader_name(arch)];
    let needed = program_needed()?;
    let (mut files, mut omitted) = (Vec::new(), Vec::new());
    for name in required {
        let preferred = (name == loader_name(arch)).then_some(preferred_loader(arch));
        match locate(root, dirs, name, preferred, trust_uid) {
            Ok(file) => files.push(file),
            Err(fail) => return Err(fail.message(name, dirs, preferred)),
        }
    }
    for name in OPTIONAL_LIBRARIES {
        let must = library_required(name, required[0], needed.as_deref());
        match locate(root, dirs, name, None, trust_uid) {
            Ok(file) => files.push(file),
            Err(LocateFail::Missing) if !must => {}
            Err(LocateFail::Refused { tried }) if !must => {
                omitted.push(format!("omitted library {name}, tried {tried}"))
            }
            Err(fail) => return Err(fail.message(name, dirs, None)),
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
fn tried_paths(name: &str, dirs: &[&str], preferred: Option<&str>) -> Vec<String> {
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
    tried
}

#[cfg(unix)]
fn locate(
    root: &Path,
    dirs: &[&str],
    name: &str,
    preferred: Option<&str>,
    trust_uid: u32,
) -> Result<LocatedFile, LocateFail> {
    let tried = tried_paths(name, dirs, preferred);
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
    let (info, held) = open_loader_stat(candidate).map_err(|_| ())?;
    let regular = info.st_mode & libc::S_IFMT == libc::S_IFREG;
    let owner = info.st_uid == trust_uid;
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
                held: Some(held),
            })
        }
        Err(_) => Err(()),
    }
}

pub(super) fn last_errno() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        *libc::__error()
    }
}

/// Dup `fd` to a descriptor at or above 3 and close `fd`. A held descriptor
/// in 0, 1, or 2 is replaced when the child dup2s its standard streams.
pub(super) fn owned_fd_above_stdio(fd: i32) -> Result<OwnedFd, i32> {
    if fd < 0 {
        return Err(last_errno());
    }
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    let err = last_errno();
    unsafe { libc::close(fd) };
    if dup < 0 {
        return Err(err);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

fn open_stat(path: &Path, flags: i32) -> std::io::Result<(libc::stat, OwnedFd)> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul"))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let held = owned_fd_above_stdio(fd).map_err(std::io::Error::from_raw_os_error)?;
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(held.as_raw_fd(), info.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((unsafe { info.assume_init() }, held))
}

fn hold_if(path: &Path, flags: i32, directory: bool) -> Option<OwnedFd> {
    let (info, held) = open_stat(path, flags).ok()?;
    let kind = [libc::S_IFREG, libc::S_IFDIR][usize::from(directory)];
    (info.st_mode & libc::S_IFMT == kind).then_some(held)
}

/// Follow a loader symlink once. The descriptor stays open, so a later name
/// at this path is a different inode and is not the rule.
fn open_loader_stat(path: &Path) -> std::io::Result<(libc::stat, OwnedFd)> {
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDONLY | libc::O_CLOEXEC;
    open_stat(path, flags)
}

/// Dup the held launch executable. A failed dup does not open the path.
/// Otherwise Linux uses `O_PATH` (`0x200000`); macOS has no `O_PATH`.
#[rustfmt::skip]
fn hold_regular_nofollow(path: &Path) -> Option<OwnedFd> {
    let launch = INTERPRETER_FD.with(|slot| slot.get());
    if launch >= 0 { let duped = unsafe { libc::fcntl(launch, libc::F_DUPFD_CLOEXEC, 3) }; return (duped >= 0).then(|| unsafe { OwnedFd::from_raw_fd(duped) }); }
    hold_if(path, [libc::O_RDONLY, 0x200000][usize::from(cfg!(target_os = "linux"))] | libc::O_CLOEXEC | libc::O_NOFOLLOW, false)
}

/// Follow the final symlink once and hold that regular file. Chain's
/// resolver names are often symlinks; the rule is the held target.
#[rustfmt::skip]
fn hold_regular_follow(path: &Path) -> Option<OwnedFd> {
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDONLY | libc::O_CLOEXEC;
    let resolv = path.as_os_str() == "/etc/resolv.conf";
    let opened = if resolv { super::chain_resolver::resolv_conf_path() } else { path.to_path_buf() };
    let read = open_stat(&opened, flags).ok();
    if resolv {
        elastos_common::resolv::note_opened_resolv(&opened, read.as_ref().map(|(i, _)| loader_identity(i)));
    }
    read.filter(|(i, _)| i.st_mode & libc::S_IFMT == libc::S_IFREG).map(|(_, fd)| fd)
}

#[cfg(any(target_os = "linux", test))]
fn hold_directory_path(path: &Path) -> Option<OwnedFd> {
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;
    hold_if(path, flags, true)
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
        let list = tried_paths(name, dirs, preferred).join(", ");
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
#[derive(Debug)]
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
    /// The descriptor opened at the check, one per rule. The child adds the
    /// Landlock rule from this descriptor and does not open the path again.
    pub held: Vec<Option<OwnedFd>>,
}

impl PartialEq for Plan {
    fn eq(&self, other: &Self) -> bool {
        self.abi == other.abi
            && self.handled == other.handled
            && self.rules == other.rules
            && self.storage_dev == other.storage_dev
            && self.storage_ino == other.storage_ino
            && self.root_dev == other.root_dev
            && self.root_ino == other.root_ino
            && self.file_pins == other.file_pins
            && self.omitted_libraries == other.omitted_libraries
    }
}

impl Eq for Plan {}

/// The storage directory opened before launch, with that directory's identity.
#[cfg(target_os = "linux")]
pub(super) struct StorageRoot<'a> {
    pub path: &'a std::path::Path,
    pub dev: u64,
    pub ino: u64,
}

#[cfg(any(target_os = "linux", test))]
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
#[cfg(target_os = "linux")]
pub(super) fn kernel_abi() -> Result<u32, String> {
    query_abi().map_err(|_| NO_LANDLOCK.to_string())
}

#[cfg(all(test, not(target_os = "linux")))]
fn query_abi() -> io::Result<u32> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(all(test, not(target_os = "linux")))]
pub(super) fn kernel_abi() -> Result<u32, String> {
    Err(NO_LANDLOCK.to_string())
}

/// `NoNewPrivs: 1` and `Seccomp: 2` (filter mode) are the confined child.
/// Anything else is a refusal the parent names.
#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
pub(super) fn build(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    bindings: &Bindings,
    abi: u32,
) -> Result<Plan, String> {
    build_for_arch(provider, admitted, bindings, LoaderArch::host(), abi)
}

#[cfg(any(target_os = "linux", test))]
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
    let mut held = Vec::new();
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
                    held.push(
                        take_checked_directory()
                            .or_else(|| hold_directory_path(&bindings.storage_root)),
                    );
                }
                r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"# => {
                    rules.push(PathRule(
                        "PROVIDER_EXECUTABLE",
                        bindings.provider_executable.clone(),
                        BINARY,
                    ));
                    file_pins.push(None);
                    held.push(hold_regular_nofollow(&bindings.provider_executable));
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
        held.push(file.held);
    }
    let plan = Plan {
        abi,
        handled: handled_fs(abi),
        rules,
        storage_dev: bindings.storage_dev,
        storage_ino: bindings.storage_ino,
        root_dev: Vec::new(),
        root_ino: Vec::new(),
        file_pins,
        omitted_libraries: planned.omitted,
        held,
    };
    remember_omitted(&plan.omitted_libraries);
    Ok(plan)
}

/// One helper directory, with the device and inode of that directory.
pub(super) struct AllowRoot {
    pub name: &'static str,
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    /// Opened at the check and held until the rule is added.
    pub held: Option<OwnedFd>,
}

pub(super) fn build_path_allow_plan(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    roots: &mut [AllowRoot],
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
    let mut held = Vec::with_capacity(roots.len() + 4);
    let mut root_dev = Vec::with_capacity(roots.len());
    let mut root_ino = Vec::with_capacity(roots.len());
    let mut omitted_libraries = Vec::new();
    if storage {
        for root in roots.iter_mut() {
            if !root.path.is_absolute() {
                return Err(format!(
                    "provider start is refused: {} is not an absolute Landlock root",
                    root.name
                ));
            }
            // ElastOS/System is read-only. Landlock cannot carve Auth out of it.
            let access = [STORAGE, READ_FILE | 8][usize::from(root.name == "ElastOS_System")];
            rules.push(PathRule(root.name, root.path.clone(), access));
            file_pins.push(None);
            held.push(root.held.take());
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
        held.push(hold_regular_nofollow(executable));
        let planned = plan_loaders(provider, LoaderArch::host())?;
        for file in planned.files {
            let pin = file.pinned.then_some((file.dev, file.ino));
            rules.push(PathRule("LANDLOCK_LOADER_PATHS", file.path, BINARY));
            file_pins.push(pin);
            held.push(file.held);
        }
        omitted_libraries = planned.omitted;
    }
    if matches!(provider, RuntimeProviderId::Chain) {
        for path in CHAIN_RESOLVER_FILES {
            // Open once, follow a final symlink, and hold that file. The
            // child adds the rule from the descriptor and does not open the
            // name again.
            if let Some(fd) = hold_regular_follow(Path::new(path)) {
                rules.push(PathRule("READ_ONLY_FILE", (*path).into(), READ_FILE));
                file_pins.push(None);
                held.push(Some(fd));
            }
        }
    }
    let storage_dev = root_dev.first().copied().unwrap_or(0);
    let storage_ino = root_ino.first().copied().unwrap_or(0);
    let plan = Plan {
        abi,
        handled: handled_fs(abi),
        rules,
        storage_dev,
        storage_ino,
        root_dev,
        root_ino,
        file_pins,
        omitted_libraries,
        held,
    };
    remember_omitted(&plan.omitted_libraries);
    // The installer reads `held` on Linux. This read keeps the field live here.
    Ok((plan.held.len(), plan).1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::io::AsRawFd;
    use RuntimeProviderId::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_o_path_is_the_hold_used_when_launch_has_no_fd() {
        assert_eq!(libc::O_PATH, 0x200000);
    }

    #[test]
    fn a_wrapping_program_header_names_the_executable() {
        let err = elastos_common::elf_needed::ph_at(u64::MAX - 10, 1, 56).unwrap_err();
        assert!(
            err.contains("the executable program headers are not usable"),
            "{err}"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.elf");
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[32..40].copy_from_slice(&(u64::MAX - 20).to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let err = interpreter_of(file.as_raw_fd()).unwrap_err();
        assert!(err.contains("the executable"), "{err}");
    }

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
            held: None,
        };
        for abi in [1, 2] {
            let mut roots = [root()];
            let err =
                build_path_allow_plan(Localhost, &admitted, &mut roots, exe, abi).unwrap_err();
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
            let mut roots = [root()];
            let plan = build_path_allow_plan(Localhost, &admitted, &mut roots, exe, abi).unwrap();
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
                for rule in &plan.rules {
                    if let Some(expected_rule) = expected
                        .iter()
                        .find(|expected_rule| expected_rule.1 == rule.1)
                    {
                        assert_eq!(rule.2, expected_rule.2, "{name} {arch:?} {}", rule.1.display());
                    } else {
                        let file = rule
                            .1
                            .file_name()
                            .and_then(|file| file.to_str())
                            .unwrap_or("");
                        assert!(
                            OPTIONAL_LIBRARIES.contains(&file),
                            "{name} {arch:?} unexpected mask row {file}"
                        );
                        assert_eq!(rule.2, executable_mask, "{name} {arch:?} {file}");
                    }
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
        let mut root = [AllowRoot {
            name: "chain-provider",
            path: "/data/chain-provider".into(),
            dev: 1,
            ino: 2,
            held: None,
        }];
        let plan = build_path_allow_plan(
            Chain,
            &super::super::rights::admit_runtime_grant(Chain),
            &mut root,
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
        let mut local = [AllowRoot {
            name: "ElastOS",
            path: "/data/ElastOS".into(),
            dev: 1,
            ino: 2,
            held: None,
        }];
        let local_plan = build_path_allow_plan(
            Localhost,
            &super::super::rights::admit_runtime_grant(Localhost),
            &mut local,
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

    /// A 64-bit ELF whose `DT_NEEDED` entries are `needed`. The load is the
    /// whole file, so the string table sits inside it.
    #[cfg(unix)]
    fn elf_with_needed(needed: &[&str]) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut rels = Vec::new();
        for name in needed {
            rels.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let dyn_off = 64 + 56 * 2;
        let dyn_len = (3 + rels.len()) * 16;
        let str_off = dyn_off + dyn_len;
        let mut buf = vec![0u8; str_off + strings.len()];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&2u16.to_le_bytes());
        let write_ph = |buf: &mut [u8], at: usize, kind: u32, off: u64, size: u64| {
            buf[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            buf[at + 16..at + 24].copy_from_slice(&off.to_le_bytes());
            buf[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
        };
        let load_len = buf.len() as u64;
        write_ph(&mut buf, 64, 1, 0, load_len);
        write_ph(&mut buf, 64 + 56, 2, dyn_off as u64, dyn_len as u64);
        let mut at = dyn_off;
        let write_dyn = |buf: &mut [u8], at: &mut usize, tag: i64, val: u64| {
            buf[*at..*at + 8].copy_from_slice(&tag.to_le_bytes());
            buf[*at + 8..*at + 16].copy_from_slice(&val.to_le_bytes());
            *at += 16;
        };
        write_dyn(&mut buf, &mut at, 5, str_off as u64);
        write_dyn(&mut buf, &mut at, 10, strings.len() as u64);
        for rel in rels {
            write_dyn(&mut buf, &mut at, 1, rel);
        }
        write_dyn(&mut buf, &mut at, 0, 0);
        buf[str_off..].copy_from_slice(&strings);
        buf
    }

    /// An ELF whose dynamic section is not a table of 16-byte entries.
    #[cfg(unix)]
    fn elf_malformed_dynamic() -> Vec<u8> {
        let mut buf = vec![0u8; 64 + 56];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        buf[64..68].copy_from_slice(&2u32.to_le_bytes());
        buf[96..104].copy_from_slice(&8u64.to_le_bytes());
        buf
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

    /// The busybox:glibc row proves the planted /lib folder layout only.
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
            .all(|line| line.starts_with("omitted library ") && !line.contains("refused")));
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
        let mut allow_roots = [AllowRoot {
            name: "data",
            path: bindings.storage_root.clone(),
            dev: 1,
            ino: 2,
            held: None,
        }];
        let allow = build_path_allow_plan(
            Localhost,
            &admitted,
            &mut allow_roots,
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
        let after_accept = launch.split("return Ok(pid)").nth(1).unwrap();
        assert!(
            after_accept.contains("reap_unconfined"),
            "deleting the kill and wait leaves this row red"
        );
        let reap = source
            .split("fn reap_unconfined")
            .nth(1)
            .unwrap()
            .split("fn launch")
            .next()
            .unwrap();
        assert!(reap.contains("libc::kill") && reap.contains("libc::waitpid"));
    }

    #[test]
    fn the_installer_checks_the_planned_file_identity() {
        let source = include_str!("preexec_installer.rs");
        let install = source.split("unsafe fn install(").nth(1).unwrap();
        let body = install.split("\n#[cfg(test)]").next().unwrap();
        assert!(
            body.contains("plan.held"),
            "the child adds the rule from the descriptor held at the check"
        );
        assert!(
            !body.contains("open_pinned_regular_file"),
            "the child does not reopen the planned file by name"
        );
    }

    #[cfg(unix)]
    fn elf_file(interp: Option<&str>) -> std::fs::File {
        use std::io::Write;
        let text = interp.unwrap_or("");
        let bytes = text.as_bytes();
        let mut buf = vec![
            0u8;
            64 + if interp.is_some() {
                56 + bytes.len() + 1
            } else {
                0
            }
        ];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2;
        buf[5] = 1;
        if interp.is_some() {
            buf[32..40].copy_from_slice(&64u64.to_le_bytes());
            buf[54..56].copy_from_slice(&56u16.to_le_bytes());
            buf[56..58].copy_from_slice(&1u16.to_le_bytes());
            buf[64..68].copy_from_slice(&3u32.to_le_bytes());
            let offset = 120u64;
            buf[72..80].copy_from_slice(&offset.to_le_bytes());
            buf[96..104].copy_from_slice(&((bytes.len() + 1) as u64).to_le_bytes());
            buf[120..120 + bytes.len()].copy_from_slice(bytes);
        }
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&buf).unwrap();
        file
    }

    #[cfg(unix)]
    #[test]
    fn the_interpreter_selects_static_glibc_musl_or_refuses_the_name() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        let static_elf = elf_file(None);
        assert_eq!(
            interpreter_of(static_elf.as_raw_fd()).unwrap(),
            Interpreter::Static
        );
        let bindings = Bindings {
            storage_root: PathBuf::from("/provider/static"),
            provider_executable: PathBuf::from("/bin/static-helper"),
            storage_dev: 1,
            storage_ino: 2,
        };
        let admitted = super::super::rights::admit_runtime_grant(RuntimeProviderId::Did);
        let static_plan = with_interpreter_fd(static_elf.as_raw_fd(), || {
            build(RuntimeProviderId::Did, &admitted, &bindings, 5).unwrap()
        });
        assert!(static_plan
            .rules
            .iter()
            .all(|rule| rule.0 != "LANDLOCK_LOADER_PATHS"));

        let arch = LoaderArch::host();
        let glibc = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        for name in [loader_name(arch), "libc.so.6", "libgcc_s.so.1"] {
            plant(glibc.path(), &format!("/lib/{name}"), 0o755);
        }
        let glibc_elf = elf_file(Some(&format!("/lib/{}", loader_name(arch))));
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                set_loader_fixture(None);
            }
        }
        let _clear = Clear;
        set_loader_fixture(Some((glibc.path().to_path_buf(), uid)));
        let glibc_plan = with_interpreter_fd(glibc_elf.as_raw_fd(), || {
            build(RuntimeProviderId::Did, &admitted, &bindings, 5).unwrap()
        });
        let glibc_names: Vec<_> = glibc_plan
            .rules
            .iter()
            .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
            .map(|rule| rule.1.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(glibc_names.iter().any(|name| name == loader_name(arch)));
        assert!(glibc_names.iter().any(|name| name == "libc.so.6"));

        let musl = tempfile::tempdir().unwrap();
        let musl_name = musl_loader_name(arch);
        plant(musl.path(), &format!("/lib/{musl_name}"), 0o755);
        plant(musl.path(), "/lib/libc.so.6", 0o755);
        std::fs::set_permissions(
            musl.path().join("lib").join("libc.so.6"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        set_loader_fixture(Some((musl.path().to_path_buf(), uid)));
        let musl_elf = elf_file(Some(&format!("/lib/{musl_name}")));
        let musl_plan = with_interpreter_fd(musl_elf.as_raw_fd(), || {
            build(RuntimeProviderId::Did, &admitted, &bindings, 5).unwrap()
        });
        let musl_names: Vec<_> = musl_plan
            .rules
            .iter()
            .filter(|rule| rule.0 == "LANDLOCK_LOADER_PATHS")
            .map(|rule| rule.1.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(musl_names, vec![musl_name.to_string()]);

        let lying = "/tmp/not-a-loader.so";
        let lying_elf = elf_file(Some(lying));
        let err = with_interpreter_fd(lying_elf.as_raw_fd(), || {
            build(RuntimeProviderId::Did, &admitted, &bindings, 5).unwrap_err()
        });
        assert!(err.contains(lying), "{err}");
        assert!(
            err.contains("provider start is refused: interpreter"),
            "{err}"
        );
    }

    /// A soname is required only when the executable names it in `DT_NEEDED`.
    /// The same rows run for both architectures.
    #[cfg(unix)]
    #[test]
    fn a_library_is_required_only_when_dt_needed_names_it() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let uid = unsafe { libc::geteuid() };
        let open_elf = |bytes: &[u8]| {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            file
        };
        for arch in [LoaderArch::X86_64, LoaderArch::Aarch64] {
            let dir = match arch {
                LoaderArch::X86_64 => "/lib/x86_64-linux-gnu",
                LoaderArch::Aarch64 => "/lib/aarch64-linux-gnu",
            };
            let loader = format!("{dir}/{}", loader_name(arch));
            let libc_so = format!("{dir}/libc.so.6");
            let libgcc = format!("{dir}/libgcc_s.so.1");
            let plan = |root: &std::path::Path, program: &std::fs::File| {
                with_interpreter_fd(program.as_raw_fd(), || {
                    resolve_loader_paths(Chain, arch, root, None, uid)
                })
            };

            let missing = tempfile::tempdir().unwrap();
            plant(missing.path(), &loader, 0o755);
            plant(missing.path(), &libc_so, 0o755);
            let program = open_elf(&elf_with_needed(&["libc.so.6", "libgcc_s.so.1"]));
            let err = plan(missing.path(), &program).unwrap_err();
            assert!(
                err.contains("libgcc_s.so.1"),
                "needed and missing is refused by name: {arch:?} {err}"
            );
            assert!(err.contains("provider start is refused"), "{err}");

            let absent = tempfile::tempdir().unwrap();
            plant(absent.path(), &loader, 0o755);
            plant(absent.path(), &libc_so, 0o755);
            let program = open_elf(&elf_with_needed(&["libc.so.6"]));
            let planned = plan(absent.path(), &program).unwrap();
            assert!(
                planned
                    .files
                    .iter()
                    .any(|file| file.path.ends_with("libc.so.6")),
                "{arch:?}"
            );
            assert!(
                planned
                    .files
                    .iter()
                    .all(|file| !file.path.ends_with("libgcc_s.so.1")),
                "not needed and missing starts: {arch:?}"
            );

            let present = tempfile::tempdir().unwrap();
            plant(present.path(), &loader, 0o755);
            plant(present.path(), &libc_so, 0o755);
            plant(present.path(), &libgcc, 0o755);
            let program = open_elf(&elf_with_needed(&["libc.so.6", "libgcc_s.so.1"]));
            let planned = plan(present.path(), &program).unwrap();
            assert!(
                planned
                    .files
                    .iter()
                    .any(|file| file.path.ends_with("libgcc_s.so.1")),
                "needed and there starts: {arch:?}"
            );

            let bad = tempfile::tempdir().unwrap();
            plant(bad.path(), &loader, 0o755);
            let program = open_elf(&elf_malformed_dynamic());
            let err = plan(bad.path(), &program).unwrap_err();
            assert!(
                err.contains("the executable dynamic section is malformed"),
                "{arch:?} {err}"
            );
        }
    }

    /// A musl soname the program names is required. A group-writable copy is
    /// refused by that name. A soname the program does not name stays optional.
    #[cfg(unix)]
    #[test]
    fn a_musl_named_soname_is_required() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let uid = unsafe { libc::geteuid() };
        let open_elf = |bytes: &[u8]| {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            file
        };
        for arch in [LoaderArch::X86_64, LoaderArch::Aarch64] {
            let root = tempfile::tempdir().unwrap();
            let loader = format!("/lib/{}", musl_loader_name(arch));
            plant(root.path(), &loader, 0o755);
            plant(root.path(), "/lib/libdl.so.2", 0o775);
            let named = open_elf(&elf_with_needed(&["libdl.so.2"]));
            let err = with_interpreter_fd(named.as_raw_fd(), || {
                resolve_named(
                    Chain,
                    arch,
                    root.path(),
                    Some(&["/lib"]),
                    uid,
                    Interpreter::Musl,
                )
            })
            .unwrap_err();
            assert!(
                err.contains("libdl.so.2"),
                "a named group-writable soname is refused: {arch:?} {err}"
            );
            let plain = open_elf(&elf_with_needed(&[]));
            let planned = with_interpreter_fd(plain.as_raw_fd(), || {
                resolve_named(
                    Chain,
                    arch,
                    root.path(),
                    Some(&["/lib"]),
                    uid,
                    Interpreter::Musl,
                )
            })
            .unwrap();
            assert!(
                planned
                    .files
                    .iter()
                    .all(|file| !file.path.ends_with("libdl.so.2")),
                "an unnamed unsafe soname stays out: {arch:?}"
            );
        }
    }
}
