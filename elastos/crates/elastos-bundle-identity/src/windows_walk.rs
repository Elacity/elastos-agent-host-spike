//! Windows bundle walk. Each child opens relative to its checked parent handle.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::{
    entry_kind, entry_path, shown, unreadable, windows_handle, Budget, BundleEntry, EntryKind,
    Moment, Refusal, Tally,
};

struct Listed {
    name: OsString,
    path: String,
    kind: EntryKind,
}

struct Folder {
    handle: File,
    listing: std::vec::IntoIter<Listed>,
}

fn listed_kind(attributes: u32) -> EntryKind {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::Special("reparse point")
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        EntryKind::Directory
    } else {
        EntryKind::RegularFile
    }
}

fn checked(handle: File, listed: EntryKind, path: &str) -> Result<File, Refusal> {
    match entry_kind(&handle.metadata().map_err(|error| unreadable(path, error))?) {
        EntryKind::Special(kind) => Err(Refusal::NotRegularFile {
            path: shown(path),
            kind,
        }),
        opened if opened != listed => Err(Refusal::Changed { path: shown(path) }),
        _ => Ok(handle),
    }
}

fn bad_root(bundle: &Path, reason: &'static str) -> Refusal {
    Refusal::InvalidRootPath {
        path: bundle.display().to_string(),
        reason,
    }
}

fn local_root(bundle: &Path) -> Result<(File, Vec<File>), Refusal> {
    if matches!(bundle.components().next(), Some(Component::RootDir)) {
        return Err(bad_root(bundle, "drive letter required"));
    }
    if matches!(bundle.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_)) && !bundle.has_root())
    {
        return Err(bad_root(bundle, "drive-relative path"));
    }
    let absolute = std::path::absolute(bundle).map_err(|_| bad_root(bundle, "invalid path"))?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(bad_root(bundle, "local disk path required"));
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
        _ => return Err(bad_root(bundle, "local disk path required")),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(bad_root(bundle, "rooted disk path required"));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(name.to_owned()),
            Component::ParentDir if !names.is_empty() => {
                names.pop();
            }
            Component::CurDir => {}
            _ => return Err(bad_root(bundle, "invalid path component")),
        }
    }
    let mut disk_path = PathBuf::from(format!(r"\\?\{}:\", drive as char));
    // Ancestors deny delete but allow normal writes. The bundle tree denies both.
    let volume_share = if names.is_empty() {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(volume_share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&disk_path)
        .map_err(|error| unreadable(&disk_path.display().to_string(), error))?;
    let mut parent = checked(
        volume,
        EntryKind::Directory,
        &disk_path.display().to_string(),
    )?;
    let mut ancestors = Vec::new();
    let count = names.len();
    for (index, name) in names.into_iter().enumerate() {
        let share = if index + 1 == count {
            FILE_SHARE_READ
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        };
        let child = windows_handle::open_child(&parent, &name, true, share)
            .map_err(|error| unreadable(&disk_path.join(&name).display().to_string(), error))?;
        disk_path.push(name);
        let child = checked(
            child,
            EntryKind::Directory,
            &disk_path.display().to_string(),
        )?;
        ancestors.push(parent);
        parent = child;
    }
    Ok((parent, ancestors))
}

fn list_folder(
    handle: &File,
    prefix: &str,
    tally: &mut Tally,
) -> Result<std::vec::IntoIter<Listed>, Refusal> {
    checked_kind_for_listing(handle, prefix)?;
    let mut listing = Vec::new();
    for (name, attributes) in
        windows_handle::list(handle).map_err(|error| unreadable(prefix, error))?
    {
        let name_bytes = name.to_string_lossy().len();
        tally.entry(prefix, name_bytes)?;
        let path = entry_path(prefix, &name)?;
        listing.push(Listed {
            name,
            path,
            kind: listed_kind(attributes),
        });
    }
    Ok(listing.into_iter())
}

fn checked_kind_for_listing(handle: &File, path: &str) -> Result<(), Refusal> {
    match entry_kind(&handle.metadata().map_err(|error| unreadable(path, error))?) {
        EntryKind::Directory => Ok(()),
        EntryKind::Special(kind) => Err(Refusal::NotRegularFile {
            path: shown(path),
            kind,
        }),
        _ => Err(Refusal::Changed { path: shown(path) }),
    }
}

fn read_file(mut handle: File, path: &str, tally: &mut Tally) -> Result<Vec<u8>, Refusal> {
    let mut content = Vec::new();
    if tally.budget == Budget::UNLIMITED {
        handle
            .read_to_end(&mut content)
            .map_err(|error| unreadable(path, error))?;
        return Ok(content);
    }
    let size = handle
        .metadata()
        .map_err(|error| unreadable(path, error))?
        .len();
    tally.file(size, path)?;
    handle
        .take(size)
        .read_to_end(&mut content)
        .map_err(|error| unreadable(path, error))?;
    if content.len() as u64 != size {
        return Err(Refusal::Changed {
            path: path.to_owned(),
        });
    }
    Ok(content)
}

pub(super) fn collect_entries(
    bundle: &Path,
    observe: &mut dyn FnMut(Moment, &str),
    tally: &mut Tally,
) -> Result<Vec<BundleEntry>, Refusal> {
    let (root, _root_ancestors) = local_root(bundle)?;
    let listing = list_folder(&root, "", tally)?;
    let mut folders = vec![Folder {
        handle: root,
        listing,
    }];
    let mut entries = Vec::new();
    while let Some(folder) = folders.last_mut() {
        let Some(Listed { name, path, kind }) = folder.listing.next() else {
            folders.pop();
            continue;
        };
        if let EntryKind::Special(kind) = kind {
            return Err(Refusal::NotRegularFile { path, kind });
        }
        if kind == EntryKind::Directory {
            tally.folder(&path)?;
        }
        observe(Moment::BeforeOpen, &path);
        let share = FILE_SHARE_READ;
        let handle =
            windows_handle::open_child(&folder.handle, &name, kind == EntryKind::Directory, share)
                .map_err(|error| unreadable(&path, error))?;
        let handle = checked(handle, kind, &path)?;
        observe(Moment::AfterCheck, &path);
        if kind == EntryKind::Directory {
            let listing = list_folder(&handle, &path, tally)?;
            folders.push(Folder { handle, listing });
        } else {
            let content = read_file(handle, &path, tally)?;
            entries.push(BundleEntry { path, content });
        }
    }
    Ok(entries)
}
