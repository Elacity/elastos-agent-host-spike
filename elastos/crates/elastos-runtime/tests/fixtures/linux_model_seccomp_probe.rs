// Stand-in model provider for the Linux confined-launch route test. It answers
// each request line and records the kernel state it inherited. It writes the
// token file only when every check holds: no_new_privs is 1, the seccomp mode is
// filter (2), and an AF_INET socket is refused with EPERM.
//
// The probe is built with a bare `rustc` (no crates), so it reaches the kernel
// through raw syscalls.
use std::io::{self, BufRead as _, Write as _};

const SYS_PRCTL: i64 = if cfg!(target_arch = "x86_64") { 157 } else { 167 };
const SYS_SOCKET: i64 = if cfg!(target_arch = "x86_64") { 41 } else { 198 };
const SYS_CLOSE: i64 = if cfg!(target_arch = "x86_64") { 3 } else { 57 };
const PR_GET_NO_NEW_PRIVS: i64 = 39;
const PR_GET_SECCOMP: i64 = 21;
const AF_INET: i64 = 2;
const SOCK_STREAM: i64 = 1;
const EPERM: i64 = 1;

#[cfg(target_arch = "x86_64")]
unsafe fn syscall(number: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    result
}

#[cfg(target_arch = "aarch64")]
unsafe fn syscall(number: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "svc 0",
            inlateout("x8") number => _,
            inlateout("x0") a => result,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack)
        );
    }
    result
}

fn inherited_socket_filter() -> bool {
    let no_new_privs = unsafe { syscall(SYS_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, ) };
    let seccomp = unsafe { syscall(SYS_PRCTL, PR_GET_SECCOMP, 0, 0, 0) };
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0, 0) };
    if fd >= 0 {
        unsafe { syscall(SYS_CLOSE, fd, 0, 0, 0) };
    }
    no_new_privs == 1 && seccomp == 2 && fd == -EPERM
}

fn main() {
    if let Ok(token) = std::env::var("ELASTOS_LINUX_MODEL_PROBE_TOKEN") {
        if !token.is_empty() && inherited_socket_filter() {
            std::fs::write(&token, b"confined").unwrap();
        }
    }
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let _ = writeln!(stdout, "{{\"status\":\"ok\"}}");
        let _ = stdout.flush();
        // Shutdown gets one ok and the probe leaves, so the test can observe a
        // dead child.
        if line.contains("\"shutdown\"") {
            return;
        }
    }
}
