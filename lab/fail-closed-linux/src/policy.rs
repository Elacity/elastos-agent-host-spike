use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(crate) const FS_EXECUTE: u64 = 1 << 0;
pub(crate) const FS_READ_FILE: u64 = 1 << 2;
pub(crate) const FS_READ_DIR: u64 = 1 << 3;
/// Every filesystem right Landlock ABI 5 reports. The ruleset handles all of
/// them, so a right with no rule is refused.
pub(crate) const HANDLED_ACCESS_FS: u64 = (1 << 16) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FsRule {
    pub(crate) path: CString,
    pub(crate) access: u64,
}

/// The Landlock path rules. The caller names every path; the guard adds none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsRules {
    rules: Vec<FsRule>,
}

impl FsRules {
    pub fn new() -> Self {
        FsRules::default()
    }

    /// Execute and read one file: the provider executable.
    pub fn exec_file(self, path: &Path) -> io::Result<Self> {
        self.add(path, false, FS_EXECUTE | FS_READ_FILE)
    }

    /// Execute and read beneath a directory, such as a loader directory.
    pub fn read_exec_dir(self, path: &Path) -> io::Result<Self> {
        self.add(path, true, FS_EXECUTE | FS_READ_FILE | FS_READ_DIR)
    }

    /// Read and write beneath a directory: the storage root. Every right but
    /// execute, so a file under the root cannot start.
    pub fn read_write_dir(self, path: &Path) -> io::Result<Self> {
        self.add(path, true, HANDLED_ACCESS_FS & !FS_EXECUTE)
    }

    fn add(mut self, path: &Path, want_dir: bool, access: u64) -> io::Result<Self> {
        let is_dir = std::fs::metadata(path)?.is_dir();
        if is_dir != want_dir {
            let wanted = if want_dir { "a directory" } else { "a file" };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not {wanted}", path.display()),
            ));
        }
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))?;
        self.rules.push(FsRule { path, access });
        Ok(self)
    }

    pub(crate) fn iter(&self) -> std::slice::Iter<'_, FsRule> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// One classic BPF instruction, `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the guard targets x86_64 and aarch64 Linux only");

/// The x86-64 kernel takes an x32 system call number with this bit set.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// A seccomp filter that allows every system call except the listed ones.
/// Any other architecture is killed, and so is an x32 number on x86-64, so a
/// listed call cannot be reached by another number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompProgram {
    filter: Vec<SockFilter>,
}

impl SeccompProgram {
    pub fn deny_list(denied: &[u32], errno: u16) -> io::Result<Self> {
        let x32 = usize::from(cfg!(target_arch = "x86_64"));
        let total = 4 + x32 + denied.len() + 2;
        if total > 250 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many denied system calls",
            ));
        }
        let deny_at = total - 1;
        let to_deny = |index: usize| (deny_at - index - 1) as u8;

        let mut filter = vec![
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_ARCH,
            },
            SockFilter {
                code: BPF_JEQ_K,
                jt: 1,
                jf: 0,
                k: NATIVE_AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: OFFSET_NR,
            },
        ];
        #[cfg(target_arch = "x86_64")]
        filter.push(SockFilter {
            code: BPF_JSET_K,
            jt: to_deny(filter.len()),
            jf: 0,
            k: X32_SYSCALL_BIT,
        });
        for number in denied {
            let jt = to_deny(filter.len());
            filter.push(SockFilter {
                code: BPF_JEQ_K,
                jt,
                jf: 0,
                k: *number,
            });
        }
        filter.push(SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
        filter.push(SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | u32::from(errno),
        });
        debug_assert_eq!(filter.len(), total);
        Ok(SeccompProgram { filter })
    }

    pub fn instructions(&self) -> &[SockFilter] {
        &self.filter
    }
}

/// System calls the baseline filter refuses with `EPERM`: every socket, which
/// removes network and descriptor passing, and the cross-process calls.
pub const DEFAULT_DENIED_SYSCALLS: &[u32] = &[
    libc::SYS_socket as u32,
    libc::SYS_socketpair as u32,
    libc::SYS_connect as u32,
    libc::SYS_ptrace as u32,
    libc::SYS_process_vm_readv as u32,
    libc::SYS_process_vm_writev as u32,
    libc::SYS_pidfd_getfd as u32,
    libc::SYS_bpf as u32,
    libc::SYS_perf_event_open as u32,
];

/// What the guard applies once every layer is available.
#[derive(Clone, Debug)]
pub struct Policy {
    pub seccomp: SeccompProgram,
    pub fs: FsRules,
}

impl Policy {
    /// The baseline deny-list filter plus the caller's path rules.
    pub fn baseline(fs: FsRules) -> io::Result<Self> {
        Ok(Policy {
            seccomp: SeccompProgram::deny_list(DEFAULT_DENIED_SYSCALLS, libc::EPERM as u16)?,
            fs,
        })
    }
}
