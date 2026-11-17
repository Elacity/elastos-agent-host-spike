//! Names admitted by each Runtime provider's Linux filter.
use super::rights_table::{for_provider, RuntimeProviderId};
use super::seccomp_program::number;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // The installer is a later B3 slice.
pub(super) enum AuditArch {
    X86_64,
    Aarch64,
}

const ROOT_READ: &str = "faccessat fstat getdents64 lseek newfstatat openat openat2 pread64 read readlinkat readv statx";
const LAUNCH: &str = "arch_prctl close exit_group getrandom mmap mprotect ppoll poll rt_sigaction";
const MODEL: &str = "epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd2 exit flock geteuid munmap rename renameat rseq";

/// The lab sorts names after it joins declared rights and measured launch calls.
pub(super) fn linux_seccomp_list(
    provider: RuntimeProviderId,
    arch: AuditArch,
) -> Vec<&'static str> {
    let mut names: Vec<_> = for_provider(provider)
        .into_iter()
        .flat_map(|row| row.linux_syscalls.split_whitespace())
        .chain(ROOT_READ.split_whitespace())
        .chain(["uname", "sysinfo"])
        .chain(LAUNCH.split_whitespace())
        .collect();
    match provider {
        RuntimeProviderId::Did => {}
        RuntimeProviderId::Wallet => names.extend(["rename", "renameat"]),
        RuntimeProviderId::Model => names.extend(MODEL.split_whitespace()),
    }
    names.retain(|name| number(name, arch).is_some());
    names.sort_unstable();
    names.dedup();
    names
}
