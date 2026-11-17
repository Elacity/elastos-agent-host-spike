//! The name list the later Linux filter builder will turn into syscall numbers.
use super::rights_table::{for_provider, RuntimeProviderId};

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // The filter builder is slice 5.
pub(super) enum AuditArch {
    X86_64,
    Aarch64,
}

const ROOT_READ: &str = "faccessat fstat getdents64 lseek newfstatat openat openat2 pread64 read readlinkat readv statx";
const LAUNCH: &str = "arch_prctl close exit_group getrandom mmap mprotect ppoll poll rt_sigaction";
const MODEL: &str = "epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd2 exit flock geteuid munmap rename renameat rseq";
const X86_ONLY: &str = "arch_prctl epoll_wait mkdir poll rename unlink";

/// The lab sorts names after it joins declared rights and measured launch calls.
#[allow(dead_code)] // The filter builder is slice 5.
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
    names.retain(|name| match arch {
        AuditArch::X86_64 => *name != "renameat",
        AuditArch::Aarch64 => !X86_ONLY.split_whitespace().any(|only| only == *name),
    });
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    // The goldens are lab output. The thread-rule suffix begins at clone3 and
    // belongs to slice 5, so only the ordinary allow-list prefix is read here.
    fn golden_names(golden: &str) -> Vec<&str> {
        let prefix = golden.split("# SYS_clone3").next().unwrap();
        let mut names: Vec<_> = prefix
            .lines()
            .filter_map(|line| line.split_once("# SYS_").map(|(_, name)| name))
            .collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn all_provider_architecture_lists_equal_lab() {
        for (arch, wallet, model, rename) in [
            (
                AuditArch::X86_64,
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../capsules/wallet-provider/tests/wallet-seccomp-x86_64.golden"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../capsules/wallet-provider/tests/model-seccomp-x86_64.golden"
                )),
                "rename",
            ),
            (
                AuditArch::Aarch64,
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../capsules/wallet-provider/tests/wallet-seccomp-aarch64.golden"
                )),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../capsules/wallet-provider/tests/model-seccomp-aarch64.golden"
                )),
                "renameat",
            ),
        ] {
            let wallet = golden_names(wallet);
            let model = golden_names(model);
            let did: Vec<_> = wallet
                .iter()
                .copied()
                .filter(|name| *name != rename)
                .collect();
            assert_eq!(
                linux_seccomp_list(RuntimeProviderId::Did, arch),
                did,
                "did {arch:?}"
            );
            assert_eq!(
                linux_seccomp_list(RuntimeProviderId::Wallet, arch),
                wallet,
                "wallet {arch:?}"
            );
            assert_eq!(
                linux_seccomp_list(RuntimeProviderId::Model, arch),
                model,
                "model {arch:?}"
            );
        }
    }
}
