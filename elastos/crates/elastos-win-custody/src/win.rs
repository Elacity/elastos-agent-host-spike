//! Owner-only creates and opens. The parent module compiles this file on Windows.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use elastos_bundle_identity_windows_handle as windows_handle;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, CopySid, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSecurityDescriptor, IsValidSid,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser,
    ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_MAX_SID_SIZE, SE_DACL_PRESENT, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileDispositionInfoEx, GetFileInformationByHandleEx,
    SetFileInformationByHandle, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::name::one_component_name;
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
const OWNER_USE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// Open or create `path` as a file. The returned handle has `access` plus the
/// rights used to read the DACL. A missing parent is an error.
pub fn open_owner_file(path: &Path, access: u32, disp: Disp) -> Result<File, CustodyError> {
    open_at(path, access, disp, false)
}

/// Create `path` as a directory with the owner-only DACL. The parent must exist.
pub fn create_owner_dir(path: &Path) -> Result<File, CustodyError> {
    open_at(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        Disp::CreateNew,
        true,
    )
}

/// The handle's owner is the current user, the DACL is protected, and every ACE
/// is an allow for that owner with no inheritance flags.
pub fn verify_owner_only(file: &File, path: &Path) -> Result<(), CustodyError> {
    let user = current_user_sid().map_err(|error| io_at(path, error))?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the out pointers are live. On success `descriptor` is a LocalAlloc block.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io_at(path, io::Error::from_raw_os_error(code as i32)));
    }
    let _free = FreeLocal(descriptor);
    // SAFETY: owner and dacl point into `descriptor` until `_free` drops.
    unsafe { owner_only(path, user.as_ptr() as PSID, owner, dacl, descriptor) }
}

fn open_at(path: &Path, access: u32, disp: Disp, directory: bool) -> Result<File, CustodyError> {
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
    let file = open_leaf(&current, leaf, path, access, disp, directory)?;
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
            verify_owner_only(&file, path)?;
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
    let opened = windows_handle::open_relative(
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
    );
    match opened {
        Ok(file) => {
            if is_reparse(&file).unwrap_or(true) {
                delete_new(&file);
                return Err(reparse_at(path));
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
                delete_new(&file);
                return Err(io_at(path, io::Error::from_raw_os_error(applied as i32)));
            }
            if let Err(error) = verify_owner_only(&file, path) {
                delete_new(&file);
                return Err(error);
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
    windows_handle::open_relative(
        parent,
        name,
        windows_handle::RelativeOpen {
            access: READ_DIR | add,
            share: SHARE_DIR,
            disposition: FILE_OPEN,
            options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE,
            attributes: 0,
            security: std::ptr::null(),
        },
    )
}

fn open_any(parent: &File, name: &OsStr) -> io::Result<File> {
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

fn open_existing(parent: &File, name: &OsStr, access: u32, directory: bool) -> io::Result<File> {
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
    if matches!(path.components().next(), Some(Component::RootDir)) {
        return Err(invalid(path, "drive letter required"));
    }
    if matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) && !path.has_root()
    ) {
        return Err(invalid(path, "drive-relative path"));
    }
    let absolute = std::path::absolute(path).map_err(|error| io_at(path, error))?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid(path, "local disk path required"));
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
        _ => return Err(invalid(path, "local disk path required")),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid(path, "rooted disk path required"));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) if one_component_name(name) => names.push(name.to_owned()),
            _ => return Err(invalid(path, "invalid path component")),
        }
    }
    if names.is_empty() {
        return Err(invalid(path, "path has no file or directory name"));
    }
    Ok((drive, names))
}

struct BuiltSd {
    acl: Vec<u64>,
    sd: windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
}

fn build_sd(sid_buf: &[u64]) -> io::Result<BuiltSd> {
    let sid = sid_buf.as_ptr() as PSID;
    // SAFETY: `sid` is the aligned copy from `current_user_sid` for this call.
    let sid_len = unsafe { GetLengthSid(sid) };
    if !(12..=SECURITY_MAX_SID_SIZE).contains(&sid_len) {
        return Err(io::Error::other("current user SID is unusable"));
    }
    let acl_len =
        (std::mem::size_of::<ACL>() + std::mem::size_of::<ACE_HEADER>() + 4 + sid_len as usize + 3)
            & !3;
    let mut acl_buf = vec![0u64; acl_len.div_ceil(8)];
    let acl = acl_buf.as_mut_ptr() as *mut ACL;
    let mut sd = windows_sys::Win32::Security::SECURITY_DESCRIPTOR::default();
    let raw = std::ptr::addr_of_mut!(sd) as PSECURITY_DESCRIPTOR;
    // SAFETY: `sd` and `acl_buf` are writable and live. `sid` stays valid for the
    // returned descriptor because the caller keeps `sid_buf` until the create returns.
    // Moving `acl_buf` into `BuiltSd` keeps its heap address.
    let ok = unsafe {
        InitializeSecurityDescriptor(raw, 1) != 0
            && InitializeAcl(acl, acl_len as u32, ACL_REVISION) != 0
            && AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) != 0
            && SetSecurityDescriptorOwner(raw, sid, 0) != 0
            && SetSecurityDescriptorDacl(raw, 1, acl, 0) != 0
            && SetSecurityDescriptorControl(raw, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
            && IsValidSecurityDescriptor(raw) != 0
    };
    if !ok {
        return Err(io::Error::other(
            "owner-only security descriptor was rejected",
        ));
    }
    Ok(BuiltSd { acl: acl_buf, sd })
}

fn current_user_sid() -> io::Result<Vec<u64>> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle. OpenProcessToken writes one owned handle.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken succeeded and returned an owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0u32;
    // SAFETY: a null buffer asks for the size only.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || needed > 4096 {
        return Err(io::Error::other("current user token has no SID"));
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is writable and at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call wrote a TOKEN_USER at the start of `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    copy_sid(sid)
}

fn copy_sid(sid: PSID) -> io::Result<Vec<u64>> {
    if sid.is_null() {
        return Err(io::Error::other("current user SID is missing"));
    }
    // SAFETY: `sid` is non-null and came from the token buffer still held by the caller.
    let (len, valid) = unsafe { (GetLengthSid(sid), IsValidSid(sid) != 0) };
    if !valid || !(12..=SECURITY_MAX_SID_SIZE).contains(&len) {
        return Err(io::Error::other("current user SID is unusable"));
    }
    let mut copy = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `copy` is aligned, writable, and at least `len` bytes.
    let ok = unsafe { CopySid(len, copy.as_mut_ptr().cast(), sid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(copy)
}

struct FreeLocal(PSECURITY_DESCRIPTOR);

impl Drop for FreeLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the LocalAlloc block from a successful GetSecurityInfo.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

unsafe fn owner_only(
    path: &Path,
    user: PSID,
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(), CustodyError> {
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the live GetSecurityInfo block. `dacl` and `owner` point into it.
    let present = unsafe {
        !descriptor.is_null()
            && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
    };
    if !present {
        return Err(io_at(path, io::Error::last_os_error()));
    }
    if control & SE_DACL_PRESENT == 0 || control & SE_DACL_PROTECTED == 0 || dacl.is_null() {
        return Err(foreign(path));
    }
    // SAFETY: `owner` and `user` are non-null SIDs for this check, or `owner` is null and we stop.
    let owner_matches = unsafe { !owner.is_null() && EqualSid(owner, user) != 0 };
    if !owner_matches {
        return Err(CustodyError::NotOwner {
            path: path.display().to_string(),
        });
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is the non-null DACL inside `descriptor`.
    let listed = unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) != 0
    };
    if !listed || size.AceCount == 0 {
        return Err(foreign(path));
    }
    for index in 0..size.AceCount {
        let mut ace = std::ptr::null_mut();
        // SAFETY: `index` is below AceCount, so GetAce returns a pointer inside `dacl`.
        let got = unsafe { GetAce(dacl, index, &mut ace) != 0 && !ace.is_null() };
        if !got {
            return Err(foreign(path));
        }
        // SAFETY: the ACE header is inside the ACL at `ace`.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0 || header.AceFlags != 0 || header.AceSize < 16 {
            return Err(foreign(path));
        }
        let sid = unsafe { ace.cast::<u8>().add(8) as PSID };
        // SAFETY: the first eight SID bytes sit inside an ACE of at least 16 bytes.
        let sid_len = unsafe { GetLengthSid(sid) };
        let mask = unsafe { ace.cast::<u8>().add(4).cast::<u32>().read_unaligned() };
        if sid_len < 12
            || 8 + sid_len > u32::from(header.AceSize)
            || unsafe { EqualSid(sid, owner) } == 0
            || (mask & OWNER_USE) != OWNER_USE
        {
            return Err(foreign(path));
        }
    }
    Ok(())
}

fn delete_new(file: &File) {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE,
    };
    // SAFETY: `info` is live for this one call. The handle was opened with DELETE.
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        );
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

fn reparse_at(path: &Path) -> CustodyError {
    CustodyError::ReparsePoint {
        path: path.display().to_string(),
    }
}

fn foreign(path: &Path) -> CustodyError {
    CustodyError::ForeignDacl {
        path: path.display().to_string(),
    }
}

fn invalid(path: &Path, reason: &str) -> CustodyError {
    io_at(path, io::Error::new(io::ErrorKind::InvalidInput, reason))
}

fn io_at(path: &Path, error: io::Error) -> CustodyError {
    CustodyError::Io(io::Error::new(
        error.kind(),
        format!("{}: {error}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    const MARKER: &[u8] = b"w1-owner-bytes-stay";

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "elastos-w1-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn icacls(args: &[&str]) {
        let output = Command::new("icacls").args(args).output().expect("icacls");
        assert!(
            output.status.success(),
            "icacls {args:?}\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn grant_users_full(dir: &Path) {
        let path = dir.display().to_string();
        icacls(&[&path, "/inheritance:r"]);
        icacls(&[&path, "/grant", "*S-1-5-32-545:(OI)(CI)(F)"]);
    }

    fn junction(link: &Path, target: &Path) {
        let status = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.display().to_string(),
                &target.display().to_string(),
            ])
            .status()
            .expect("mklink");
        assert!(status.success(), "mklink /J");
    }

    fn write_marker(dir: &Path) -> std::path::PathBuf {
        let file = dir.join("kept.bin");
        std::fs::write(&file, MARKER).unwrap();
        file
    }

    #[test]
    fn junction_at_target_name_is_refused_and_bytes_stay() {
        let scratch = Scratch::new("junction-target");
        let target = scratch.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let marker = write_marker(&target);
        let link = scratch.0.join("link");
        junction(&link, &target);
        for disp in [Disp::CreateNew, Disp::OpenExisting, Disp::OpenOrCreate] {
            let error = open_owner_file(&link, OWNER_USE, disp).expect_err("junction");
            assert!(
                matches!(error, CustodyError::ReparsePoint { .. }),
                "{error}"
            );
        }
        assert_eq!(std::fs::read(marker).unwrap(), MARKER);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    }

    #[test]
    fn permissive_parent_keeps_owner_only_dacl_without_inherited_aces() {
        let scratch = Scratch::new("permissive");
        grant_users_full(&scratch.0);
        let plain = scratch.0.join("plain");
        std::fs::write(&plain, b"plain").unwrap();
        let plain_file = std::fs::File::open(&plain).unwrap();
        assert!(
            matches!(
                verify_owner_only(&plain_file, &plain),
                Err(CustodyError::ForeignDacl { .. } | CustodyError::NotOwner { .. })
            ),
            "a file created under Users full control must not pass"
        );
        let owned = scratch.0.join("owned");
        let file = open_owner_file(&owned, OWNER_USE, Disp::CreateNew).unwrap();
        verify_owner_only(&file, &owned).unwrap();
        drop(file);
        let again = open_owner_file(&owned, FILE_GENERIC_READ, Disp::OpenExisting).unwrap();
        verify_owner_only(&again, &owned).unwrap();
        let dir_path = scratch.0.join("dir");
        let dir = create_owner_dir(&dir_path).unwrap();
        verify_owner_only(&dir, &dir_path).unwrap();
    }

    #[test]
    fn reparse_point_parent_is_refused_and_bytes_stay() {
        let scratch = Scratch::new("junction-parent");
        let target = scratch.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let marker = write_marker(&target);
        let link = scratch.0.join("link");
        junction(&link, &target);
        let error =
            open_owner_file(&link.join("child"), OWNER_USE, Disp::CreateNew).expect_err("parent");
        assert!(
            matches!(error, CustodyError::ReparsePoint { .. }),
            "{error}"
        );
        let dir_error = create_owner_dir(&link.join("child-dir")).expect_err("parent dir");
        assert!(
            matches!(dir_error, CustodyError::ReparsePoint { .. }),
            "{dir_error}"
        );
        assert_eq!(std::fs::read(marker).unwrap(), MARKER);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    }

    #[test]
    fn read_back_verifies_owner_only_dacl() {
        let scratch = Scratch::new("read-back");
        let path = scratch.0.join("note");
        let mut file = open_owner_file(&path, OWNER_USE, Disp::CreateNew).unwrap();
        file.write_all(b"stay").unwrap();
        verify_owner_only(&file, &path).unwrap();
        drop(file);
        assert!(open_owner_file(&path, OWNER_USE, Disp::CreateNew).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"stay");
        let again = open_owner_file(&path, FILE_GENERIC_READ, Disp::OpenExisting).unwrap();
        verify_owner_only(&again, &path).unwrap();
        drop(again);
        let third = open_owner_file(&path, OWNER_USE, Disp::OpenOrCreate).unwrap();
        verify_owner_only(&third, &path).unwrap();
        let fresh = scratch.0.join("fresh");
        let created = open_owner_file(&fresh, OWNER_USE, Disp::OpenOrCreate).unwrap();
        verify_owner_only(&created, &fresh).unwrap();
    }

    #[test]
    fn everyone_ace_fails_verify_owner_only() {
        let scratch = Scratch::new("everyone");
        let path = scratch.0.join("note");
        let file = open_owner_file(&path, OWNER_USE, Disp::CreateNew).unwrap();
        verify_owner_only(&file, &path).unwrap();
        drop(file);
        icacls(&[&path.display().to_string(), "/grant", "*S-1-1-0:(F)"]);
        let opened = std::fs::File::open(&path).unwrap();
        let error = verify_owner_only(&opened, &path).expect_err("everyone");
        assert!(matches!(error, CustodyError::ForeignDacl { .. }), "{error}");
    }
}
