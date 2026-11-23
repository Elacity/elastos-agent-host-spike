//! Handle-relative walk, open, and create.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use elastos_bundle_identity_windows_handle as windows_handle;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileDispositionInfoEx, GetFileInformationByHandleEx,
    SetFileInformationByHandle, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};

use super::sd::{build_sd, current_user_sid, verify_not_writable_by_others, verify_owner_only};
use super::{invalid, io_at, reparse_at};
use crate::name::absolute_local_disk;
use crate::CustodyError;

/// How the final component is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disp {
    CreateNew,
    OpenExisting,
    OpenOrCreate,
}

const READ_DIR: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const SHARE_DIR: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

/// Read an existing owner-only file.
pub const READ_EXISTING: u32 = FILE_GENERIC_READ;
/// Read and write an owner-only file.
pub const READ_WRITE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// Open or create `path` as a file. The returned handle has `access` plus the
/// rights used to read the DACL. A missing parent is an error.
pub fn open_owner_file(path: &Path, access: u32, disp: Disp) -> Result<File, CustodyError> {
    open_at(path, access, disp, false, true)
}

/// Create `path` as a directory with the owner-only DACL. The parent must exist.
pub fn create_owner_dir(path: &Path) -> Result<File, CustodyError> {
    open_at(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        Disp::CreateNew,
        true,
        true,
    )
}

/// Open an existing directory and require the owner-only DACL.
pub fn open_owner_dir(path: &Path) -> Result<File, CustodyError> {
    open_at(path, FILE_GENERIC_READ, Disp::OpenExisting, true, true)
}

/// The directory is not a reparse point. The current user owns it. No ACE grants
/// write to anyone except that user, SYSTEM, and Administrators.
///
/// A directory Home creates still uses [`create_owner_dir`]. This check is only
/// for a directory that already existed, such as the operator data root.
pub fn refuse_other_writers(path: &Path) -> Result<(), CustodyError> {
    let file = open_at(path, FILE_GENERIC_READ, Disp::OpenExisting, true, false)?;
    verify_not_writable_by_others(&file, path)
}

fn open_at(
    path: &Path,
    access: u32,
    disp: Disp,
    directory: bool,
    owner_only: bool,
) -> Result<File, CustodyError> {
    let (drive, names) = local_names(path)?;
    let (leaf, parents) = names
        .split_last()
        .ok_or_else(|| invalid(path, "path has no file or directory name"))?;
    let add = if directory {
        FILE_ADD_SUBDIRECTORY
    } else {
        FILE_ADD_FILE
    };
    let add = if matches!(disp, Disp::OpenExisting) {
        0
    } else {
        add
    };
    let root = PathBuf::from(format!("{}:\\", drive as char));
    let mut current = open_volume(drive, if parents.is_empty() { add } else { 0 })
        .map_err(|error| io_at(&root, error))?;
    if is_reparse(&current).map_err(|error| io_at(&root, error))? {
        return Err(reparse_at(&root));
    }
    let mut walked = root;
    let mut kept = Vec::new();
    for (index, name) in parents.iter().enumerate() {
        walked.push(name);
        let parent_add = if index + 1 == parents.len() { add } else { 0 };
        let child = open_parent(&current, name, parent_add, &walked)?;
        kept.push(std::mem::replace(&mut current, child));
    }
    let file = open_leaf(&current, leaf, path, access, disp, directory, owner_only)?;
    drop(kept);
    Ok(file)
}

fn open_leaf(
    parent: &File,
    name: &OsStr,
    path: &Path,
    access: u32,
    disp: Disp,
    directory: bool,
    owner_only: bool,
) -> Result<File, CustodyError> {
    match open_any(parent, name) {
        Ok(found) => {
            let (reparse, is_dir) = flags(&found).map_err(|error| io_at(path, error))?;
            drop(found);
            if reparse {
                return Err(reparse_at(path));
            }
            if is_dir != directory {
                let kind = if is_dir {
                    io::ErrorKind::IsADirectory
                } else {
                    io::ErrorKind::NotADirectory
                };
                return Err(io_at(path, io::Error::new(kind, "owner-only open kind")));
            }
            if disp == Disp::CreateNew {
                return Err(io_at(
                    path,
                    io::Error::new(io::ErrorKind::AlreadyExists, "already exists"),
                ));
            }
            let file = open_existing(parent, name, access, directory)
                .map_err(|error| io_at(path, error))?;
            if is_reparse(&file).map_err(|error| io_at(path, error))? {
                return Err(reparse_at(path));
            }
            if owner_only {
                verify_owner_only(&file, path)?;
            }
            Ok(file)
        }
        Err(error) if missing(&error) => {
            if disp == Disp::OpenExisting {
                Err(io_at(path, error))
            } else {
                create_new(parent, name, path, access, directory)
            }
        }
        Err(error) => Err(io_at(path, error)),
    }
}

fn create_new(
    parent: &File,
    name: &OsStr,
    path: &Path,
    access: u32,
    directory: bool,
) -> Result<File, CustodyError> {
    let sid = current_user_sid().map_err(|error| io_at(path, error))?;
    let built = build_sd(&sid).map_err(|error| io_at(path, error))?;
    // `sid` and `built` stay in this frame for the create and the apply below.
    // SAFETY: `built.sd` is an absolute descriptor. `built` and `sid` stay in this
    // frame, so the descriptor and the SID it points at stay live for the call.
    let opened = unsafe {
        windows_handle::open_relative(
            parent,
            name,
            windows_handle::RelativeOpen {
                access: access
                    | READ_CONTROL
                    | WRITE_DAC
                    | WRITE_OWNER
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE
                    | DELETE,
                share: SHARE_DIR,
                disposition: FILE_CREATE,
                options: leaf_options(directory),
                attributes: FILE_ATTRIBUTE_NORMAL,
                security: std::ptr::addr_of!(built.sd),
            },
        )
    };
    match opened {
        Ok(file) => {
            if is_reparse(&file).unwrap_or(true) {
                return Err(remove_failed_new(file, reparse_at(path)));
            }
            // SAFETY: the handle is the new object. `sid` and `built.acl` stay live for the call.
            let applied = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    sid.as_ptr() as PSID,
                    std::ptr::null_mut(),
                    built.acl.as_ptr().cast(),
                    std::ptr::null(),
                )
            };
            if applied != 0 {
                return Err(remove_failed_new(
                    file,
                    io_at(path, io::Error::from_raw_os_error(applied as i32)),
                ));
            }
            if let Err(error) = verify_created(&file, path) {
                return Err(remove_failed_new(file, error));
            }
            Ok(file)
        }
        Err(error) => {
            if exists(&error) {
                if let Ok(found) = open_any(parent, name) {
                    if is_reparse(&found).unwrap_or(false) {
                        return Err(reparse_at(path));
                    }
                }
            }
            Err(io_at(path, error))
        }
    }
}

fn verify_created(file: &File, path: &Path) -> Result<(), CustodyError> {
    #[cfg(test)]
    if FAIL_NEXT_CREATED_VERIFY.with(|flag| flag.replace(false)) {
        return Err(super::foreign(path));
    }
    verify_owner_only(file, path)
}

/// The next create reports a foreign DACL from verify, after the object exists.
/// The Windows delete test sets this. Production builds omit it.
#[cfg(test)]
pub(super) fn fail_next_created_verify() {
    FAIL_NEXT_CREATED_VERIFY.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn clear_created_verify_failure() {
    FAIL_NEXT_CREATED_VERIFY.with(|flag| flag.set(false));
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_CREATED_VERIFY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn open_parent(parent: &File, name: &OsStr, add: u32, path: &Path) -> Result<File, CustodyError> {
    let child = match open_dir(parent, name, add) {
        Ok(child) => child,
        Err(error) => {
            if let Ok(any) = open_any(parent, name) {
                if is_reparse(&any).unwrap_or(false) {
                    return Err(reparse_at(path));
                }
            }
            return Err(io_at(path, error));
        }
    };
    let (reparse, is_dir) = flags(&child).map_err(|error| io_at(path, error))?;
    if reparse {
        return Err(reparse_at(path));
    }
    if !is_dir {
        return Err(io_at(
            path,
            io::Error::new(io::ErrorKind::NotADirectory, "parent is not a directory"),
        ));
    }
    Ok(child)
}

fn open_volume(drive: u8, add: u32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .access_mode(READ_DIR | add)
        .share_mode(SHARE_DIR)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(format!(r"\\?\{}:\", drive as char))
}

fn open_dir(parent: &File, name: &OsStr, add: u32) -> io::Result<File> {
    // SAFETY: `security` is null. The kernel reads no security descriptor.
    unsafe {
        windows_handle::open_relative(
            parent,
            name,
            windows_handle::RelativeOpen {
                access: READ_DIR | add,
                share: SHARE_DIR,
                disposition: FILE_OPEN,
                options: FILE_SYNCHRONOUS_IO_NONALERT
                    | FILE_OPEN_REPARSE_POINT
                    | FILE_DIRECTORY_FILE,
                attributes: 0,
                security: std::ptr::null(),
            },
        )
    }
}

fn open_any(parent: &File, name: &OsStr) -> io::Result<File> {
    // SAFETY: `security` is null. The kernel reads no security descriptor.
    unsafe {
        windows_handle::open_relative(
            parent,
            name,
            windows_handle::RelativeOpen {
                access: FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                share: SHARE_DIR | FILE_SHARE_DELETE,
                disposition: FILE_OPEN,
                options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                attributes: 0,
                security: std::ptr::null(),
            },
        )
    }
}

fn open_existing(parent: &File, name: &OsStr, access: u32, directory: bool) -> io::Result<File> {
    // SAFETY: `security` is null. The kernel reads no security descriptor.
    unsafe {
        windows_handle::open_relative(
            parent,
            name,
            windows_handle::RelativeOpen {
                access: access | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                share: SHARE_DIR,
                disposition: FILE_OPEN,
                options: leaf_options(directory),
                attributes: 0,
                security: std::ptr::null(),
            },
        )
    }
}

fn leaf_options(directory: bool) -> u32 {
    FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        }
}

fn local_names(path: &Path) -> Result<(u8, Vec<std::ffi::OsString>), CustodyError> {
    absolute_local_disk(path.as_os_str()).map_err(|reason| invalid(path, reason))
}

fn remove_failed_new(file: File, error: CustodyError) -> CustodyError {
    let error = match delete_new(&file) {
        Ok(()) => error,
        Err(cleanup) => error.with_failed_cleanup(cleanup),
    };
    // Close the handle so a successful delete removes the name before we return.
    drop(file);
    error
}

fn delete_new(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE,
    };
    // SAFETY: `info` is live for this one call. The handle was opened with DELETE.
    let deleted = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if deleted == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn attributes(file: &File) -> io::Result<u32> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `info` is writable, aligned, and live for this one call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.FileAttributes)
}

fn flags(file: &File) -> io::Result<(bool, bool)> {
    let bits = attributes(file)?;
    Ok((
        bits & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        bits & FILE_ATTRIBUTE_DIRECTORY != 0,
    ))
}

fn is_reparse(file: &File) -> io::Result<bool> {
    Ok(flags(file)?.0)
}

fn missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || matches!(error.raw_os_error(), Some(2 | 3))
}

fn exists(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists
        || matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
        )
}
