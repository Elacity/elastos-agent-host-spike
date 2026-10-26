use std::ffi::CStr;
use std::mem::size_of;

use crate::guard::{Errno, Kernel};
use crate::policy::{FsRules, SeccompProgram, SockFilter, HANDLED_ACCESS_FS};

const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_ulong = 1;
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// The real kernel of this host. Each method is a thin system call wrapper.
pub struct HostKernel {
    uid: u32,
    gid: u32,
}

impl HostKernel {
    /// Read the caller's ids now: after `unshare` they read as the overflow id
    /// until the maps are written, and the maps need the original ids.
    pub fn new() -> Self {
        // SAFETY: `getuid` and `getgid` cannot fail.
        unsafe {
            HostKernel {
                uid: libc::getuid(),
                gid: libc::getgid(),
            }
        }
    }
}

impl Default for HostKernel {
    fn default() -> Self {
        HostKernel::new()
    }
}

fn errno() -> Errno {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn push_decimal(mut value: u32, out: &mut [u8; 48], at: &mut usize) {
    let mut digits = [0u8; 10];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
        if value == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        out[*at] = digits[count];
        *at += 1;
    }
}

/// `"<id> <id> 1\n"`: map one id to itself, so file ownership is unchanged.
fn id_map_line(id: u32, out: &mut [u8; 48]) -> usize {
    let mut at = 0;
    push_decimal(id, out, &mut at);
    out[at] = b' ';
    at += 1;
    push_decimal(id, out, &mut at);
    out[at..at + 3].copy_from_slice(b" 1\n");
    at + 3
}

fn write_proc_file(path: &CStr, data: &[u8]) -> Result<(), Errno> {
    // SAFETY: plain system calls on a NUL-terminated path and a live buffer.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(errno());
        }
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let error = errno();
        libc::close(fd);
        if written < 0 {
            return Err(error);
        }
        if written as usize != data.len() {
            return Err(libc::EIO);
        }
    }
    Ok(())
}

impl Kernel for HostKernel {
    fn landlock_abi(&self) -> Result<u32, Errno> {
        // SAFETY: the version query takes a null attribute and size 0.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0 as libc::size_t,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 0 {
            Err(errno())
        } else {
            Ok(abi as u32)
        }
    }

    fn unshare_user(&self) -> Result<(), Errno> {
        // SAFETY: `unshare` takes flags only.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn map_ids(&self) -> Result<(), Errno> {
        let mut line = [0u8; 48];
        write_proc_file(c"/proc/self/setgroups", b"deny")?;
        let len = id_map_line(self.gid, &mut line);
        write_proc_file(c"/proc/self/gid_map", &line[..len])?;
        let len = id_map_line(self.uid, &mut line);
        write_proc_file(c"/proc/self/uid_map", &line[..len])
    }

    fn drop_capabilities(&self) -> Result<(), Errno> {
        // SAFETY: `prctl` and `capset` take integers and live structures.
        unsafe {
            for cap in 0..64 as libc::c_ulong {
                let held = libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0);
                if held < 0 {
                    let error = errno();
                    if error == libc::EINVAL {
                        break;
                    }
                    return Err(error);
                }
                if held == 1 && libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 {
                    return Err(errno());
                }
            }
            let header = CapHeader {
                version: CAPABILITY_VERSION_3,
                pid: 0,
            };
            let data = [CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) < 0 {
                return Err(errno());
            }
        }
        Ok(())
    }

    fn set_no_new_privs(&self) -> Result<(), Errno> {
        // SAFETY: `prctl` takes integers.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) } < 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn install_seccomp(&self, program: &SeccompProgram) -> Result<(), Errno> {
        let instructions = program.instructions();
        let prog = SockFprog {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
        };
        // SAFETY: `prog` points at `instructions`, which outlive the call.
        let seccomp_rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0 as libc::c_long,
                &prog as *const SockFprog,
            )
        };
        if seccomp_rc < 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    fn landlock_restrict(&self, rules: &FsRules) -> Result<(), Errno> {
        let attr = RulesetAttr {
            handled_access_fs: HANDLED_ACCESS_FS,
        };
        // SAFETY: each call takes a live structure or a descriptor this
        // function owns, and every descriptor is closed before return.
        unsafe {
            let ruleset = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size_of::<RulesetAttr>(),
                0 as libc::c_ulong,
            );
            if ruleset < 0 {
                return Err(errno());
            }
            let ruleset = ruleset as libc::c_int;
            let mut result = Ok(());
            for rule in rules.iter() {
                let parent = libc::open(rule.path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                if parent < 0 {
                    result = Err(errno());
                    break;
                }
                let beneath = PathBeneath {
                    allowed_access: rule.access,
                    parent_fd: parent,
                };
                let rc = libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &beneath as *const PathBeneath,
                    0 as libc::c_ulong,
                );
                let error = errno();
                libc::close(parent);
                if rc < 0 {
                    result = Err(error);
                    break;
                }
            }
            if result.is_ok()
                && libc::syscall(
                    libc::SYS_landlock_restrict_self,
                    ruleset,
                    0 as libc::c_ulong,
                ) < 0
            {
                result = Err(errno());
            }
            libc::close(ruleset);
            result
        }
    }
}
