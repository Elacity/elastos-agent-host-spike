//! The seccomp layer's filter.
//!
//! A foreign architecture kills the process. On x86-64 every x32 system call
//! returns EPERM. The system calls in `DENIED`, and `clone` with any
//! namespace flag, return EPERM; `clone3` returns ENOSYS so the C library
//! falls back to `clone`, whose flags the filter can read. Every other system
//! call is allowed: this is a deny-list for network sockets and sandbox
//! escapes, not a per-provider allow-list.

use libc::{
    sock_filter, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
};

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xC000_00B7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Offsets into `struct seccomp_data`. The low half of `args[0]` is at 16 on
/// little-endian targets, which both supported targets are.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARG0_LOW: u32 = 16;
const DATA_ARG0_HIGH: u32 = 20;

pub const DENIED: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_kexec_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_open_by_handle_at,
    libc::SYS_io_uring_setup,
];

/// `CLONE_NEWTIME` is left out: in `clone` its bit belongs to the exit signal.
const CLONE_NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

fn stmt(code: u32, k: u32) -> sock_filter {
    sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

pub fn filter() -> Vec<sock_filter> {
    let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let enosys = SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    let mut prog = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, DATA_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        prog.push(jump(BPF_JMP | libc::BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, eperm));
    }
    for &nr in DENIED {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, eperm));
    }
    // Deny any later PR_SET_DUMPABLE. The helper already set dumpable to 0.
    // 0: JEQ prctl, 0, 4  -> not prctl jumps to clone3
    // 1: LD ARG0_LOW
    // 2: JEQ PR_SET_DUMPABLE, 0, 1 -> other prctl jumps to ALLOW
    // 3: RET EPERM
    // 4: RET ALLOW
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_prctl as u32,
        0,
        4,
    ));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARG0_LOW));
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::PR_SET_DUMPABLE as u32,
        0,
        1,
    ));
    prog.push(stmt(BPF_RET | BPF_K, eperm));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone3 as u32,
        0,
        1,
    ));
    prog.push(stmt(BPF_RET | BPF_K, enosys));
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone as u32,
        0,
        3,
    ));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARG0_LOW));
    prog.push(jump(
        BPF_JMP | BPF_JSET | BPF_K,
        CLONE_NAMESPACE_FLAGS,
        0,
        1,
    ));
    prog.push(stmt(BPF_RET | BPF_K, eperm));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog
}

/// Second filter, installed after confine and before the helper's `execve`.
///
/// `execveat` returns EPERM. `execve` returns EPERM unless `argv[0]` / the
/// pathname pointer is the granted path the helper already holds. That one
/// call is the confined program's own initial exec. After the image is
/// replaced the pointer is gone, so a later pathname exec of the granted
/// binary and `execve("/proc/self/fd/N")` of a memfd both return EPERM.
/// Stacked on the deny-list: if this install fails, launch refuses.
pub fn no_exec_filter(granted_path: u64) -> Vec<sock_filter> {
    let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let path_lo = granted_path as u32;
    let path_hi = (granted_path >> 32) as u32;
    let mut prog = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, DATA_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        prog.push(jump(BPF_JMP | libc::BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, eperm));
    }
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_execveat as u32,
        0,
        1,
    ));
    prog.push(stmt(BPF_RET | BPF_K, eperm));
    // execve: allow only the helper's granted-path pointer, then ALLOW.
    // 0: JEQ execve, 0, 4  -> not execve jumps to ALLOW
    // 1: LD ARG0_LOW
    // 2: JEQ path_lo, 0, 3 -> mismatch jumps to EPERM
    // 3: LD ARG0_HIGH
    // 4: JEQ path_hi, 0, 1 -> mismatch jumps to EPERM
    // 5: RET ALLOW
    // 6: RET EPERM
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_execve as u32,
        0,
        4,
    ));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARG0_LOW));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, path_lo, 0, 3));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_ARG0_HIGH));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, path_hi, 0, 1));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET | BPF_K, eperm));
    prog
}
