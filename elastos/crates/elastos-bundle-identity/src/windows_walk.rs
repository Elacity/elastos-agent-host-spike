//! Windows bundle walk. Checked directory handles pin every path component.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ,
};

use super::{
    entry_path, shown, unreadable, Budget, BundleEntry, EntryKind, Moment, Refusal, Tally,
};

struct Listed {
    name: OsString,
    path: String,
    kind: EntryKind,
}

struct Folder {
    _handle: File,
    disk_path: PathBuf,
    listing: std::vec::IntoIter<Listed>,
}

fn kind(meta: &Metadata) -> EntryKind {
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::Special("reparse point")
    } else if meta.is_dir() {
        EntryKind::Directory
    } else if meta.is_file() {
        EntryKind::RegularFile
    } else {
        EntryKind::Special("special file")
    }
}

// OPEN_REPARSE_POINT protects the last component. Every earlier component has
// already been checked and is held with no write/delete sharing.
fn open_checked(disk_path: &Path, listed: EntryKind, path: &str) -> Result<File, Refusal> {
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(disk_path)
        .map_err(|error| unreadable(path, error))?;
    match kind(&handle.metadata().map_err(|error| unreadable(path, error))?) {
        EntryKind::Special(kind) => Err(Refusal::NotRegularFile {
            path: shown(path),
            kind,
        }),
        opened if opened != listed => Err(Refusal::Changed { path: shown(path) }),
        _ => Ok(handle),
    }
}

fn local_root(bundle: &Path) -> Result<(PathBuf, Vec<File>), Refusal> {
    let absolute = std::path::absolute(bundle).map_err(|error| unreadable("", error))?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(unreadable(
            "",
            io::Error::other("bundle needs a local disk path"),
        ));
    };
    let Prefix::Disk(drive) = prefix.kind() else {
        return Err(unreadable(
            "",
            io::Error::other("bundle needs a local disk path"),
        ));
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(unreadable(
            "",
            io::Error::other("bundle needs a rooted disk path"),
        ));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(name.to_owned()),
            Component::ParentDir if !names.is_empty() => {
                names.pop();
            }
            Component::CurDir => {}
            _ => return Err(unreadable("", io::Error::other("invalid bundle path"))),
        }
    }
    // Verbatim opens preserve names that Win32 would trim or treat as DOS devices.
    let mut disk_path = PathBuf::from(format!(r"\\?\{}:\", drive as char));
    let mut handles = vec![open_checked(&disk_path, EntryKind::Directory, "")?];
    for name in names {
        disk_path.push(name);
        handles.push(open_checked(&disk_path, EntryKind::Directory, "")?);
    }
    Ok((disk_path, handles))
}

fn list_folder(
    disk_path: &Path,
    prefix: &str,
    tally: &mut Tally,
) -> Result<std::vec::IntoIter<Listed>, Refusal> {
    let mut listing = Vec::new();
    for item in fs::read_dir(disk_path).map_err(|error| unreadable(prefix, error))? {
        let item = item.map_err(|error| unreadable(prefix, error))?;
        let name = item.file_name();
        let name_bytes = name.to_string_lossy().len();
        tally.entry(prefix, name_bytes)?;
        let path = entry_path(prefix, &name)?;
        let meta = fs::symlink_metadata(item.path()).map_err(|error| unreadable(&path, error))?;
        listing.push(Listed {
            name,
            path,
            kind: kind(&meta),
        });
    }
    Ok(listing.into_iter())
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
    let (root_path, mut root_handles) = local_root(bundle)?;
    let root = root_handles.pop().expect("volume root was opened");
    // Earlier root components stay pinned until the whole walk ends.
    let _root_ancestors = root_handles;
    let listing = list_folder(&root_path, "", tally)?;
    let mut folders = vec![Folder {
        _handle: root,
        disk_path: root_path,
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
        let disk_path = folder.disk_path.join(name);
        let handle = open_checked(&disk_path, kind, &path)?;
        observe(Moment::AfterCheck, &path);
        if kind == EntryKind::Directory {
            let listing = list_folder(&disk_path, &path, tally)?;
            folders.push(Folder {
                _handle: handle,
                disk_path,
                listing,
            });
        } else {
            let content = read_file(handle, &path, tally)?;
            entries.push(BundleEntry { path, content });
        }
    }
    Ok(entries)
}
