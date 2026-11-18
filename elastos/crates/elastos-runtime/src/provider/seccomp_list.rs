//! Names admitted by each Runtime provider's Linux filter.
use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use super::seccomp_program::number;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // The installer is a later B3 slice.
pub(super) enum AuditArch {
    X86_64,
    Aarch64,
}

/// Every filter includes this list, whether or not a row was admitted.
///
/// `read` is the reply on fd 0. `write` and `writev` are the reply on fds 1–2
/// and the child's fixed failure record. The other names are the root-read and
/// launch calls every provider already had. They live here so dropping a row,
/// including `storage`, cannot drop the reply channel.
const BASELINE: &str = concat!(
    "read readv write writev ",
    "faccessat fstat getdents64 lseek newfstatat openat openat2 pread64 readlinkat statx ",
    "uname sysinfo ",
    "arch_prctl close exit_group getrandom mmap mprotect ppoll poll rt_sigaction",
);

const MODEL: &str = "epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd2 exit flock geteuid munmap rename renameat rseq";

/// The lab sorts names after it joins declared rights and the baseline.
pub(super) fn linux_seccomp_list(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    arch: AuditArch,
) -> Vec<&'static str> {
    let mut names: Vec<_> = admitted
        .rows()
        .iter()
        .flat_map(|row| row.linux_syscalls.split_whitespace())
        .chain(BASELINE.split_whitespace())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_executable_only() -> AdmittedRights {
        let path = format!(
            "{}/../../../capsules/did-provider/capsule.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let json = std::fs::read_to_string(&path).unwrap();
        let mut manifest: elastos_common::CapsuleManifest = serde_json::from_str(&json).unwrap();
        let mut authority = manifest.authority.take().unwrap();
        authority
            .rights
            .retain(|right| right.id == "bound-executable");
        super::super::rights::check_rights_against_runtime_templates(
            RuntimeProviderId::Did,
            &authority,
            super::super::rights_table::RIGHTS,
        )
        .unwrap()
    }

    #[test]
    fn bound_executable_plan_contains_write_and_writev() {
        let admitted = bound_executable_only();
        for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
            let names = linux_seccomp_list(RuntimeProviderId::Did, &admitted, arch);
            assert!(
                names.contains(&"write") && names.contains(&"writev"),
                "the protocol baseline keeps write and writev"
            );
            assert!(
                !names.contains(&"pwrite64"),
                "storage calls stay with the storage row"
            );
        }
    }
}
