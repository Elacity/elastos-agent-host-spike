//! Handle-relative walk, open, and create.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
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
    FileAttributeTagInfo, FileDispositionInfoEx, FileRenameInfo, GetFileInformationByHandleEx,
    SetFileInformationByHandle, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
    WRITE_OWNER,
};

use super::sd::{build_sd, current_user_sid, verify_not_writable_by_others, verify_owner_only};
use super::{invalid, io_at, reparse_at};
use crate::name::{absolute_local_disk, one_component_name};
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
    open_at(path, access, disp, false, true, false)
}

/// Read an existing owner-only file while this process already holds it open.
///
/// Create opens the handle with `DELETE`. A later [`open_owner_file`] does not
/// share delete, so it cannot open that same name until the first handle
/// closes. The lock re-check uses this open.
pub fn reopen_owner_file(path: &Path) -> Result<File, CustodyError> {
    open_at(path, READ_EXISTING, Disp::OpenExisting, false, true, true)
}

/// Create `path` as a directory with the owner-only DACL. The parent must exist.
pub fn create_owner_dir(path: &Path) -> Result<File, CustodyError> {
    open_at(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        Disp::CreateNew,
        true,
        true,
        false,
    )
}

/// Open an existing directory and require the owner-only DACL.
pub fn open_owner_dir(path: &Path) -> Result<File, CustodyError> {
    open_at(
        path,
        FILE_GENERIC_READ,
        Disp::OpenExisting,
        true,
        true,
        false,
    )
}

/// The directory is not a reparse point. The current user owns it. No ACE grants
/// write to anyone except that user, SYSTEM, and Administrators.
///
/// A directory Home creates still uses [`create_owner_dir`]. This check is only
/// for a directory that already existed, such as the operator data root.
pub fn refuse_other_writers(path: &Path) -> Result<(), CustodyError> {
    let file = open_at(
        path,
        FILE_GENERIC_READ,
        Disp::OpenExisting,
        true,
        false,
        false,
    )?;
    verify_not_writable_by_others(&file, path)
}

/// Open an existing file or directory under the accepted data root rule.
///
/// The walk is handle-relative from the volume root and a reparse point on any
/// component is refused. The leaf must exist as the requested kind and must not
/// be writable by anyone except its owner, SYSTEM, and Administrators — the W2
/// accepted-root rule — so files that carry inherited SYSTEM or Administrators
/// ACEs open, while a Users-writable file is refused. Unlike
/// [`open_owner_file`] it does not require the owner-only DACL.
pub fn open_accepted_file(path: &Path, access: u32, directory: bool) -> Result<File, CustodyError> {
    let file = open_at(path, access, Disp::OpenExisting, directory, false, false)?;
    verify_not_writable_by_others(&file, path)?;
    Ok(file)
}

/// Rename the open file `source` to `dest_name` inside `directory`.
///
/// The directory open is handle-relative. A reparse point on the directory,
/// on `source`, or on `dest_name` is refused. `dest_name` is one component.
/// The file keeps the security descriptor it already has; this call does not
/// write a new DACL. When `replace_existing` is false, an existing destination
/// is left in place.
///
/// `source` must be a handle from [`open_owner_file`] with [`Disp::CreateNew`]:
/// that open includes `DELETE`, which the rename requires. A later slice can
/// use `replace_existing` for an owner-only file in the same directory.
pub fn rename_owner_file(
    directory: &Path,
    source: &File,
    source_path: &Path,
    dest_name: &OsStr,
    replace_existing: bool,
) -> Result<(), CustodyError> {
    if !one_component_name(dest_name) {
        return Err(invalid(
            &directory.join(dest_name),
            "child name is not one component",
        ));
    }
    if is_reparse(source).map_err(|error| io_at(source_path, error))? {
        return Err(reparse_at(source_path));
    }
    verify_owner_only(source, source_path)?;
    let dir = open_at(
        directory,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        Disp::OpenExisting,
        true,
        true,
        false,
    )?;
    let dest_path = directory.join(dest_name);
    match open_any(&dir, dest_name) {
        Ok(found) => {
            let (reparse, is_dir) = flags(&found).map_err(|error| io_at(&dest_path, error))?;
            drop(found);
            if reparse {
                return Err(reparse_at(&dest_path));
            }
            if is_dir {
                return Err(io_at(
                    &dest_path,
                    io::Error::new(io::ErrorKind::IsADirectory, "owner-only rename destination"),
                ));
            }
            if !replace_existing {
                return Err(io_at(
                    &dest_path,
                    io::Error::new(io::ErrorKind::AlreadyExists, "already exists"),
                ));
            }
            let existing = open_existing(&dir, dest_name, FILE_GENERIC_READ, false, false)
                .map_err(|error| io_at(&dest_path, error))?;
            verify_owner_only(&existing, &dest_path)?;
            drop(existing);
        }
        Err(error) if missing(&error) => {}
        Err(error) => return Err(io_at(&dest_path, error)),
    }
    rename_handle(&dir, source, dest_name, replace_existing)
        .map_err(|error| io_at(&dest_path, error))
}

/// Mark `file` for deletion. The name is removed when its last handle closes.
///
/// `file` must have been opened with `DELETE`, which an owner-only create is.
/// The delete is the open handle, not a path lookup.
pub fn discard_owner_file(file: &File, path: &Path) -> Result<(), CustodyError> {
    delete_new(file).map_err(|error| io_at(path, error))
}

fn open_at(
    path: &Path,
    access: u32,
    disp: Disp,
    directory: bool,
    owner_only: bool,
    share_delete: bool,
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
    let file = open_leaf(
        &current,
        leaf,
        path,
        LeafOpen {
            access,
            disp,
            directory,
            owner_only,
            share_delete,
        },
    )?;
    drop(kept);
    Ok(file)
}

struct LeafOpen {
    access: u32,
    disp: Disp,
    directory: bool,
    owner_only: bool,
    share_delete: bool,
}

fn open_leaf(
    parent: &File,
    name: &OsStr,
    path: &Path,
    leaf: LeafOpen,
) -> Result<File, CustodyError> {
    let LeafOpen {
        access,
        disp,
        directory,
        owner_only,
        share_delete,
    } = leaf;
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
            let file = open_existing(parent, name, access, directory, share_delete)
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

fn open_existing(
    parent: &File,
    name: &OsStr,
    access: u32,
    directory: bool,
    share_delete: bool,
) -> io::Result<File> {
    let share = SHARE_DIR | if share_delete { FILE_SHARE_DELETE } else { 0 };
    // SAFETY: `security` is null. The kernel reads no security descriptor.
    unsafe {
        windows_handle::open_relative(
            parent,
            name,
            windows_handle::RelativeOpen {
                access: access | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                share,
                disposition: FILE_OPEN,
                options: leaf_options(directory),
                attributes: 0,
                security: std::ptr::null(),
            },
        )
    }
}

fn rename_handle(
    directory: &File,
    source: &File,
    dest_name: &OsStr,
    replace_existing: bool,
) -> io::Result<()> {
    let mut wide: Vec<u16> = dest_name.encode_wide().collect();
    if wide.is_empty() || wide.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child name is not one component",
        ));
    }
    // FileName is a NUL-terminated wide string. FileNameLength excludes the NUL.
    wide.push(0);
    let name_bytes = ((wide.len() - 1) * 2) as u32;
    const REPLACE_AT: usize = std::mem::offset_of!(FILE_RENAME_INFO, Anonymous);
    const ROOT_AT: usize = std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory);
    const LEN_AT: usize = std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength);
    const NAME_AT: usize = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    const ROOT_LEN: usize = std::mem::size_of::<usize>();
    const _: () = assert!(REPLACE_AT + 4 <= ROOT_AT);
    const _: () = assert!(ROOT_AT + ROOT_LEN <= LEN_AT);
    const _: () = assert!(LEN_AT + 4 <= NAME_AT);
    let total = NAME_AT + wide.len() * 2;
    let mut storage = vec![0u64; total.div_ceil(std::mem::size_of::<u64>())];
    // SAFETY: `storage` is zeroed, 8-byte aligned, and at least `total` bytes.
    // The slice is that prefix. Field offsets come from `FILE_RENAME_INFO`, whose
    // alignment is 8. Bytes are copied into those offsets; the name occupies the
    // flexible `FileName` tail, including its NUL. Both handles stay live for the
    // one `SetFileInformationByHandle` call.
    let renamed = unsafe {
        let buf = std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), total);
        buf[REPLACE_AT..REPLACE_AT + 4].copy_from_slice(&u32::from(replace_existing).to_ne_bytes());
        let root = directory.as_raw_handle() as usize;
        buf[ROOT_AT..ROOT_AT + ROOT_LEN].copy_from_slice(&root.to_ne_bytes());
        buf[LEN_AT..LEN_AT + 4].copy_from_slice(&name_bytes.to_ne_bytes());
        let name = std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2);
        buf[NAME_AT..NAME_AT + name.len()].copy_from_slice(name);
        SetFileInformationByHandle(
            source.as_raw_handle(),
            FileRenameInfo,
            storage.as_ptr().cast(),
            total as u32,
        )
    };
    if renamed == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
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
