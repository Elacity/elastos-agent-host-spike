//! Owner-only security descriptor: build it, copy the user SID, and check it.
#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_ALL, GENERIC_WRITE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, CopySid, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACE_HEADER, ACL, ACL_REVISION,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{foreign, io_at};
use crate::CustodyError;

pub(super) const OWNER_USE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// Write rights that let another user add, replace, or retarget a child.
const OTHER_WRITE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL
    | 0x0200_0000;

pub(super) struct BuiltSd {
    pub(super) acl: Vec<u64>,
    pub(super) sd: windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
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

/// The current user owns `file`, and no other user is granted write.
///
/// SYSTEM and Administrators may hold write. A user profile and its temp
/// directory grant those two principals write; refusing them would reject every
/// empty temp directory. A new Home file still has to pass [`verify_owner_only`].
pub(super) fn verify_not_writable_by_others(file: &File, path: &Path) -> Result<(), CustodyError> {
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
    unsafe { no_other_writers(path, user.as_ptr() as PSID, owner, dacl, descriptor) }
}

pub(super) fn build_sd(sid_buf: &[u64]) -> io::Result<BuiltSd> {
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

pub(super) fn current_user_sid() -> io::Result<Vec<u64>> {
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
    if descriptor.is_null() {
        return Err(io_at(
            path,
            io::Error::other("security descriptor is missing"),
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the live GetSecurityInfo block. `dacl` and `owner` point into it.
    // GetSecurityDescriptorControl does not reliably set the last error.
    let read =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0 };
    if !read {
        return Err(io_at(
            path,
            io::Error::other("security descriptor control is unreadable"),
        ));
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

unsafe fn no_other_writers(
    path: &Path,
    user: PSID,
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(), CustodyError> {
    if descriptor.is_null() {
        return Err(io_at(
            path,
            io::Error::other("security descriptor is missing"),
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is the live GetSecurityInfo block. `dacl` and `owner` point into it.
    // GetSecurityDescriptorControl does not reliably set the last error.
    let read =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0 };
    if !read {
        return Err(io_at(
            path,
            io::Error::other("security descriptor control is unreadable"),
        ));
    }
    if control & SE_DACL_PRESENT == 0 || dacl.is_null() {
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
    if !listed {
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
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // Deny ACEs do not grant write. Anything other than a plain allow is refused.
        if header.AceType == 1 {
            continue;
        }
        if header.AceType != 0 || header.AceSize < 16 {
            return Err(foreign(path));
        }
        let sid = unsafe { ace.cast::<u8>().add(8) as PSID };
        // SAFETY: the first eight SID bytes sit inside an ACE of at least 16 bytes.
        let sid_len = unsafe { GetLengthSid(sid) };
        let mask = unsafe { ace.cast::<u8>().add(4).cast::<u32>().read_unaligned() };
        if sid_len < 12 || 8 + sid_len > u32::from(header.AceSize) {
            return Err(foreign(path));
        }
        if mask & OTHER_WRITE == 0 {
            continue;
        }
        // SAFETY: `sid` and `user` are non-null and sized above. IsWellKnownSid only reads `sid`.
        let allowed = unsafe {
            EqualSid(sid, user) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        };
        if !allowed {
            return Err(foreign(path));
        }
    }
    Ok(())
}
