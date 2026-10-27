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
use std::os::raw::c_char;

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xC000_00B7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Offsets into `struct seccomp_data`. The low half of `args[0]` is at 16 on
/// little-endian targets, which both supported targets are. `args[1]` is at 24.
/// `instruction_pointer` is the 64-bit field at offset 8.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_IP_LOW: u32 = 8;
const DATA_IP_HIGH: u32 = 12;
const DATA_ARG0_LOW: u32 = 16;

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

/// Address of the one `syscall`/`svc` that may `execve` the granted image.
/// After that image replaces this helper, the address is gone.
pub fn first_exec_ip() -> u64 {
    first_exec_syscall as usize as u64
}

/// The only instruction the no-exec filter allows to issue `execve`.
///
/// The filter compares `seccomp_data.instruction_pointer` to this symbol.
/// The syscall must be the first instruction so the IP matches.
///
/// # Safety
///
/// The caller must put the `execve` number and arguments in the syscall
/// registers before entering this gadget.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "C" fn first_exec_syscall() {
    core::arch::naked_asm!("syscall", "ret")
}

/// The only instruction the no-exec filter allows to issue `execve`.
///
/// # Safety
///
/// The caller must put the `execve` number and arguments in the syscall
/// registers before entering this gadget.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
pub unsafe extern "C" fn first_exec_syscall() {
    core::arch::naked_asm!("svc #0", "ret")
}

/// Issues the confined program's own initial `execve` from `first_exec_syscall`.
///
/// The no-exec filter must already be installed. Any later `execve` comes
/// from another IP and returns EPERM.
///
/// # Safety
///
/// `pathname`, `argv` and `envp` must be valid NULL-terminated C strings
/// for the duration of the call, matching `execve(2)`.
pub unsafe fn execve_once(
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> isize {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::asm!(
            "call {gadget}",
            gadget = sym first_exec_syscall,
            in("rax") libc::SYS_execve,
            in("rdi") pathname,
            in("rsi") argv,
            in("rdx") envp,
            lateout("rax") ret,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        core::arch::asm!(
            "blr x9",
            in("x9") first_exec_syscall as usize,
            in("x8") libc::SYS_execve,
            in("x0") pathname,
            in("x1") argv,
            in("x2") envp,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// Second filter, installed after confine and before the one-shot trampoline.
///
/// `execveat` returns EPERM. `execve` returns EPERM unless the instruction
/// pointer is `first_exec_ip()`, which is the helper's own initial exec of
/// the granted path. After that exec the trampoline is gone, so a later
/// pathname exec of the granted binary and `execve("/proc/self/fd/N")` of a
/// memfd both return EPERM. Stacked on the deny-list: if this install fails,
/// launch refuses.
pub fn no_exec_filter(first_exec_ip: u64) -> Vec<sock_filter> {
    let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let ip_lo = first_exec_ip as u32;
    let ip_hi = (first_exec_ip >> 32) as u32;
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
    // execve: allow only the trampoline IP, then ALLOW. Any other IP is EPERM.
    // 0: JEQ execve, 0, 5  -> not execve jumps to ALLOW
    // 1: LD IP_LOW
    // 2: JEQ ip_lo, 0, 3   -> mismatch jumps to EPERM
    // 3: LD IP_HIGH
    // 4: JEQ ip_hi, 0, 1   -> mismatch jumps to EPERM
    // 5: RET ALLOW
    // 6: RET EPERM
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_execve as u32,
        0,
        5,
    ));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_IP_LOW));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, ip_lo, 0, 3));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, DATA_IP_HIGH));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, ip_hi, 0, 1));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET | BPF_K, eperm));
    prog
}
