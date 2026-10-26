//! Fd-relative path walk from a capsule root.
//!
//! Every component is opened from the parent fd. The walk never re-resolves a
//! string path after the root fd is held. Linux uses `openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` when the
//! kernel accepts it. Otherwise each component uses `openat` with
//! `O_NOFOLLOW` (and `O_DIRECTORY` for intermediate names) plus `fstat`.

use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsFd;
use std::path::Path;

use rustix::fs::{mkdirat, openat, openat2, readlinkat, renameat, Dir, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use crate::Refuse;

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

const FILE_READ: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

const FILE_WRITE: OFlags = OFlags::RDWR.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

const FILE_CREATE: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) fn open_root(path: &Path) -> Result<fs::File, Refuse> {
    // The root is already a canonical real directory. openat2(RESOLVE_BENEATH)
    // from CWD refuses an absolute path, so the root fd is opened with openat.
    let fd = openat(rustix::fs::CWD, path, DIR_FLAGS, Mode::empty()).map_err(map_io)?;
    to_file(fd)
}

pub(crate) fn open_existing_file(
    root: &fs::File,
    parts: &[impl AsRef<OsStr>],
) -> Result<fs::File, Refuse> {
    let (parent, name) = walk_parent(root, parts, false)?;
    let fd = open_one(parent, name, FILE_READ, Mode::empty())?;
    to_file(fd)
}

pub(crate) fn open_or_create_file(
    root: &fs::File,
    parts: &[impl AsRef<OsStr>],
) -> Result<fs::File, Refuse> {
    let (parent, name) = walk_parent(root, parts, true)?;
    match openat2(
        &parent,
        name,
        FILE_CREATE,
        Mode::from_raw_mode(0o644),
        RESOLVE,
    ) {
        Ok(fd) => return to_file(fd),
        Err(err) if err == Errno::EXIST => {}
        Err(err) if err == Errno::NOSYS || err == Errno::INVAL => {
            match openat(&parent, name, FILE_CREATE, Mode::from_raw_mode(0o644)) {
                Ok(fd) => return to_file(fd),
                Err(err) if err == Errno::EXIST => {}
                Err(err) => return Err(map_open_err(&parent, name, err)),
            }
        }
        Err(err) => return Err(map_open_err(&parent, name, err)),
    }
    let fd = open_one(parent, name, FILE_WRITE, Mode::empty())?;
    to_file(fd)
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
    match open_one(&parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Refuse::NotFound) if create => {
            match mkdirat(&parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) => {}
                Err(err) if err == Errno::EXIST => {}
                Err(err) => return Err(map_open_err(&parent, name, err)),
            }
            open_one(parent, name, DIR_FLAGS, Mode::empty())
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
    match openat2(&dir, name, oflags, mode, RESOLVE) {
        Ok(fd) => Ok(fd),
        Err(err) if err == Errno::NOSYS || err == Errno::INVAL => {
            openat(&dir, name, oflags, mode).map_err(|e| map_open_err(&dir, name, e))
        }
        Err(err) => Err(map_open_err(&dir, name, err)),
    }
}

fn map_open_err<Fd: AsFd, P: rustix::path::Arg + Copy>(dir: Fd, name: P, err: Errno) -> Refuse {
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
