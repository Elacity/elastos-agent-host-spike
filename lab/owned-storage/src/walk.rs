//! Fd-relative path walk from a capsule root.
//!
//! Every component is opened from the parent fd. The walk never re-resolves a
//! string path after the root fd is held. Linux uses `openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//! RESOLVE_NO_XDEV` when the kernel accepts it. Otherwise each component uses
//! `openat` with `O_NOFOLLOW` (and `O_DIRECTORY` for intermediate names).
//! `RESOLVE_NO_XDEV` refuses a bind-mount of another tree under the root.

use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsFd;
use std::path::Path;

use rustix::fs::{mkdirat, openat, openat2, readlinkat, renameat, Dir, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::Refuse;

const DIR_BASE: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

const FILE_READ_BASE: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC);

const FILE_WRITE_BASE: OFlags = OFlags::RDWR.union(OFlags::CLOEXEC);

const FILE_CREATE_BASE: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC);

/// Live last-component and directory opens add this flag. Plant `F-A9-nofollow`
/// / mutant `M-no-nofollow` drop it here, on the path `open_one` actually uses.
pub(crate) fn nofollow_flag() -> OFlags {
    OFlags::NOFOLLOW
}

/// Live `openat2` resolve set. Mutant `M-walk-no-symlinks` drops `NO_SYMLINKS`.
/// Plant `F-A9-no-xdev` / `F-A9-bind-mount` drop `NO_XDEV`.
pub(crate) fn resolve_no_xdev() -> bool {
    true
}

pub(crate) fn resolve_flags() -> ResolveFlags {
    let mut flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);
    if resolve_no_xdev() {
        flags = flags.union(ResolveFlags::NO_XDEV);
    }
    flags
}

/// Live opens try `openat2` first. Mutant `M-walk-force-openat` turns this off.
pub(crate) fn openat2_first() -> bool {
    true
}

pub(crate) enum OpenedFile {
    Created(fs::File),
    Existing(fs::File),
}

impl OpenedFile {
    pub(crate) fn file(self) -> fs::File {
        match self {
            Self::Created(file) | Self::Existing(file) => file,
        }
    }
}

pub(crate) fn open_root(path: &Path) -> Result<fs::File, Refuse> {
    // The root is already a canonical real directory. openat2(RESOLVE_BENEATH)
    // from CWD refuses an absolute path, so the root fd is opened with openat.
    let fd = openat(
        rustix::fs::CWD,
        path,
        DIR_BASE.union(nofollow_flag()),
        Mode::empty(),
    )
    .map_err(map_io)?;
    to_file(fd)
}

pub(crate) fn open_existing_file(
    root: &fs::File,
    parts: &[impl AsRef<OsStr>],
) -> Result<fs::File, Refuse> {
    let (parent, name) = walk_parent(root, parts, false)?;
    let fd = open_one(parent, name, FILE_READ_BASE, Mode::empty())?;
    to_file(fd)
}

pub(crate) fn open_or_create_file(
    root: &fs::File,
    parts: &[impl AsRef<OsStr>],
) -> Result<OpenedFile, Refuse> {
    let (parent, name) = walk_parent(root, parts, true)?;
    match try_open(&parent, name, FILE_CREATE_BASE, Mode::from_raw_mode(0o644)) {
        Ok(fd) => return Ok(OpenedFile::Created(to_file(fd)?)),
        Err(err) if err == Errno::EXIST => {}
        Err(err) => return Err(map_open_err(&parent, name, err)),
    }
    let fd = open_one(parent, name, FILE_WRITE_BASE, Mode::empty())?;
    Ok(OpenedFile::Existing(to_file(fd)?))
}

pub(crate) fn open_dir(root: &fs::File, parts: &[impl AsRef<OsStr>]) -> Result<fs::File, Refuse> {
    if parts.is_empty() {
        return root.try_clone().map_err(|_| Refuse::OutsideRoot);
    }
    let fd = walk_dir(root, parts, false)?;
    to_file(fd)
}

pub(crate) fn list_names(dir: &fs::File) -> Result<Vec<String>, Refuse> {
    let cloned = dir.try_clone().map_err(|_| Refuse::OutsideRoot)?;
    let iter = Dir::read_from(cloned).map_err(|_| Refuse::OutsideRoot)?;
    let mut names = Vec::new();
    for entry in iter {
        let entry = entry.map_err(|_| Refuse::OutsideRoot)?;
        let name = entry.file_name().to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.into_owned());
    }
    names.sort();
    Ok(names)
}

pub(crate) fn rename_rel(
    root: &fs::File,
    from: &[impl AsRef<OsStr>],
    to: &[impl AsRef<OsStr>],
) -> Result<(), Refuse> {
    let (src_parent, src_name) = walk_parent(root, from, false)?;
    let (dst_parent, dst_name) = walk_parent(root, to, true)?;
    renameat(src_parent, src_name, dst_parent, dst_name).map_err(map_io)
}

fn walk_parent<'a>(
    root: &fs::File,
    parts: &'a [impl AsRef<OsStr>],
    create_dirs: bool,
) -> Result<(rustix::fd::OwnedFd, &'a OsStr), Refuse> {
    if parts.is_empty() {
        return Err(Refuse::HostPath);
    }
    let name = parts[parts.len() - 1].as_ref();
    if name.is_empty() || name == "." || name == ".." {
        return Err(Refuse::HostPath);
    }
    let parent = if parts.len() == 1 {
        dup_fd(root)?
    } else {
        walk_dir(root, &parts[..parts.len() - 1], create_dirs)?
    };
    Ok((parent, name))
}

fn walk_dir(
    root: &fs::File,
    parts: &[impl AsRef<OsStr>],
    create_dirs: bool,
) -> Result<rustix::fd::OwnedFd, Refuse> {
    let mut current = dup_fd(root)?;
    for part in parts {
        let name = part.as_ref();
        if name.is_empty() || name == "." || name == ".." {
            return Err(Refuse::HostPath);
        }
        current = open_or_mkdir(current, name, create_dirs)?;
    }
    Ok(current)
}

fn open_or_mkdir(
    parent: rustix::fd::OwnedFd,
    name: &OsStr,
    create: bool,
) -> Result<rustix::fd::OwnedFd, Refuse> {
    match open_one(&parent, name, DIR_BASE, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Refuse::NotFound) if create => {
            match mkdirat(&parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) => {}
                Err(err) if err == Errno::EXIST => {}
                Err(err) => return Err(map_open_err(&parent, name, err)),
            }
            open_one(parent, name, DIR_BASE, Mode::empty())
        }
        Err(other) => Err(other),
    }
}

fn open_one<Fd: AsFd, P: rustix::path::Arg + Copy>(
    dir: Fd,
    name: P,
    oflags: OFlags,
    mode: Mode,
) -> Result<rustix::fd::OwnedFd, Refuse> {
    try_open(&dir, name, oflags, mode).map_err(|e| map_open_err(&dir, name, e))
}

fn try_open<Fd: AsFd, P: rustix::path::Arg + Copy>(
    dir: Fd,
    name: P,
    oflags: OFlags,
    mode: Mode,
) -> Result<rustix::fd::OwnedFd, Errno> {
    let oflags = oflags.union(nofollow_flag());
    if openat2_first() {
        match openat2(&dir, name, oflags, mode, resolve_flags()) {
            Ok(fd) => Ok(fd),
            Err(err) if err == Errno::NOSYS || err == Errno::INVAL => {
                openat(&dir, name, oflags, mode)
            }
            Err(err) => Err(err),
        }
    } else {
        openat(&dir, name, oflags, mode)
    }
}

fn map_open_err<Fd: AsFd, P: rustix::path::Arg + Copy>(dir: Fd, name: P, err: Errno) -> Refuse {
    if err == Errno::XDEV {
        return Refuse::CrossMount;
    }
    if err == Errno::LOOP || err == Errno::NOTEMPTY || err == Errno::INVAL {
        if let Ok(target) = readlinkat(&dir, name, Vec::new()) {
            if crate::is_shared_temp(Path::new(target.to_string_lossy().as_ref())) {
                return Refuse::SharedTemp;
            }
            return Refuse::Symlink;
        }
        if err == Errno::LOOP {
            return Refuse::Symlink;
        }
    }
    map_io(err)
}

fn map_io(err: Errno) -> Refuse {
    if err == Errno::NOENT {
        Refuse::NotFound
    } else if err == Errno::LOOP {
        Refuse::Symlink
    } else if err == Errno::XDEV {
        Refuse::CrossMount
    } else {
        Refuse::OutsideRoot
    }
}

fn dup_fd(file: &fs::File) -> Result<rustix::fd::OwnedFd, Refuse> {
    rustix::io::dup(file).map_err(|_| Refuse::OutsideRoot)
}

fn to_file(fd: rustix::fd::OwnedFd) -> Result<fs::File, Refuse> {
    Ok(fs::File::from(fd))
}
