//! The Windows handle boundary: one-component opens and enumeration of that handle.
//! The caller supplies a name from a validated root or checked listing. This
//! crate also rejects separators, streams and dot components before the open.
//!
//! Safety of each unsafe block:
//! 1. `NtCreateFile` gets live object attributes, name storage, status storage,
//!    a borrowed parent handle, and a null or caller-owned security descriptor
//!    for one synchronous call.
//! 2. `RtlNtStatusToDosErrorNoTeb` accepts the returned NTSTATUS value.
//! 3. `OwnedHandle::from_raw_handle` takes sole ownership after a successful
//!    open that returned a non-null handle.
//! 4. `GetFileInformationByHandleEx` gets a live, writable, aligned buffer
//!    and its actual byte length for one synchronous call.
//! 5. `read_unaligned` reads a directory record only after its full range is
//!    checked inside the initialized buffer.
//! 6. `from_raw_parts` reads a UTF-16 name only after its even length and
//!    bounds are checked; the buffer stays immutable while the slice lives.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, RtlNtStatusToDosErrorNoTeb, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, UNICODE_STRING};
use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
use windows_sys::Win32::Storage::FileSystem::{
    FileIdBothDirectoryInfo, GetFileInformationByHandleEx, FILE_ID_BOTH_DIR_INFO,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0};

/// One handle-relative open. `security` is null, or an absolute security
/// descriptor that stays live for this synchronous call. [`open_child`] passes null.
pub struct RelativeOpen {
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub attributes: u32,
    pub security: *const SECURITY_DESCRIPTOR,
}

pub fn open_child(parent: &File, name: &OsStr, directory: bool, share: u32) -> io::Result<File> {
    open_relative(
        parent,
        name,
        RelativeOpen {
            access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share,
            disposition: FILE_OPEN,
            options: FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            attributes: 0,
            security: std::ptr::null(),
        },
    )
}

pub fn open_relative(parent: &File, name: &OsStr, open: RelativeOpen) -> io::Result<File> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty()
        || matches!(wide.as_slice(), [46] | [46, 46])
        || wide.iter().any(|&unit| matches!(unit, 0 | 47 | 58 | 92))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child name is not one component",
        ));
    }
    let bytes = wide
        .len()
        .checked_mul(2)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "child name too long"))?;
    let name = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: 0, // Exact listed spelling also works in case-sensitive directories.
        SecurityDescriptor: open.security,
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw = std::ptr::null_mut();
    let mut iosb = IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
        Information: 0,
    };
    // SAFETY: all pointers remain live for this synchronous call; RootDirectory
    // is the held parent, and the caller supplies one path component. A non-null
    // security descriptor is an absolute descriptor the caller keeps alive.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            open.access,
            &attrs,
            &mut iosb,
            std::ptr::null(),
            open.attributes,
            open.share,
            open.disposition,
            open.options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: RtlNtStatusToDosErrorNoTeb accepts any NTSTATUS value.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosErrorNoTeb(status) } as i32,
        ));
    }
    if raw.is_null() {
        return Err(io::Error::other("NtCreateFile returned no handle"));
    }
    // SAFETY: successful NtCreateFile returned one owned handle in `raw`.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

pub fn list(handle: &File) -> io::Result<Vec<(OsString, u32)>> {
    let mut entries = Vec::new();
    let mut buffer = [0u64; 8192];
    let bytes = size_of_val(&buffer);
    let name_at = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    loop {
        // SAFETY: the buffer is writable, 8-byte aligned and live for the call.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle(),
                FileIdBothDirectoryInfo,
                buffer.as_mut_ptr().cast(),
                bytes as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(entries)
            } else {
                Err(error)
            };
        }
        let mut offset = 0usize;
        loop {
            if offset + size_of::<FILE_ID_BOTH_DIR_INFO>() > bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short directory record",
                ));
            }
            // SAFETY: the checked range is initialized and within the buffer.
            let info = unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>()
                    .read_unaligned()
            };
            let len = info.FileNameLength as usize;
            if !len.is_multiple_of(2) || len > bytes - offset - name_at {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory name",
                ));
            }
            // SAFETY: FileNameLength was checked against the buffer boundary.
            let wide = unsafe {
                std::slice::from_raw_parts(
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset + name_at)
                        .cast::<u16>(),
                    len / 2,
                )
            };
            let name = OsString::from_wide(wide);
            if name != "." && name != ".." {
                entries.push((name, info.FileAttributes));
            }
            let next = info.NextEntryOffset as usize;
            if next == 0 {
                break;
            }
            if next < size_of::<FILE_ID_BOTH_DIR_INFO>()
                || next > bytes - offset
                || !next.is_multiple_of(2)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory offset",
                ));
            }
            offset += next;
        }
    }
}
