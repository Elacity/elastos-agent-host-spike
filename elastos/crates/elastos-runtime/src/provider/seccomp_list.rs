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

// Linux probe rows follow the original model names. `socket` is absent from
// this model list: the model program admits it only for AF_UNIX, in the
// argument rules. `connect`, `sendto` and `bind` stay, because the probe
// measured them and they do not carry an address family.
const MODEL: &str = "epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd2 exit flock geteuid munmap rename renameat rseq accept4 bind connect dup2 getpgrp getpid getsockopt listen pipe2 readlink recvfrom rt_sigprocmask sendto setpgid waitid";

/// Names the provider declares, before an unlisted name is dropped.
///
/// `abi_required` reads this list. A declared `ioctl` still selects Landlock
/// ABI 5 when `number` has no row for it, and the filter below does not admit
/// that name.
pub(super) fn declared_linux_names(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
) -> Vec<&'static str> {
    let mut names: Vec<_> = admitted
        .rows()
        .iter()
        .flat_map(|row| row.linux_syscalls.split_whitespace())
        .chain(BASELINE.split_whitespace())
        .chain(provider.measured_syscalls().split_whitespace())
        .collect();
    match provider {
        RuntimeProviderId::Did
        | RuntimeProviderId::Localhost
        | RuntimeProviderId::Object
        | RuntimeProviderId::Chain => {}
        RuntimeProviderId::Wallet => names.extend(["rename", "renameat"]),
        RuntimeProviderId::Model => names.extend(MODEL.split_whitespace()),
    }
    names
}

/// The lab sorts names after it joins declared rights and the baseline.
pub(super) fn linux_seccomp_list(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    arch: AuditArch,
) -> Vec<&'static str> {
    let mut names = declared_linux_names(provider, admitted);
    names.retain(|name| number(name, arch).is_some());
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const MODEL_PROBE_NAMES: &str = "accept4 bind connect dup2 getpgrp getpid getsockopt listen pipe2 readlink recvfrom rt_sigprocmask sendto setpgid waitid";

    // Normalization: only LAB_BASELINE is subtracted from the crate side. The pin set stays as derived.
    // `did` has none. A mismatch prints the symmetric difference. The baseline check does not apply that delta.

    fn pin(path: &str) -> String {
        let spec = format!("d0dd5693:{path}");
        let out = crate::provider::rights::git_show(&spec);
        assert!(out.status.success(), "pin {spec} missing: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("pin d0dd5693")
    }
    fn part<'a>(src: &'a str, marker: &str) -> &'a str {
        let at = src.find(marker).unwrap_or_else(|| panic!("pin d0dd5693 missing {marker}"));
        let rest = &src[at..];
        &rest[..rest.find("];").unwrap_or_else(|| panic!("pin d0dd5693: {marker}"))]
    }
    fn calls(block: &str) -> Vec<&str> {
        let (mut names, mut rest) = (Vec::new(), block);
        while let Some(start) = rest.find('"') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('"') else { break };
            let name = &rest[..end];
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') { names.push(name); }
            rest = &rest[end + 1..];
        }
        names
    }
    fn raws(block: &str) -> Vec<&str> {
        let (mut forms, mut rest) = (Vec::new(), block);
        while let Some(start) = rest.find("r#\"") {
            rest = &rest[start + 3..];
            let end = rest.find("\"#").unwrap_or_else(|| panic!("pin d0dd5693 raw string"));
            forms.push(&rest[..end]);
            rest = &rest[end + 2..];
        }
        forms
    }
    fn number_rows(block: &str) -> Vec<(&str, bool, bool)> {
        block.split("(\"").skip(1).map(|row| {
            let name = row.split('"').next().unwrap();
            let mut cells = row.split(',');
            let _ = cells.next();
            (name, cells.next().unwrap_or_else(|| panic!("pin d0dd5693 number {name}")).contains("Some"), cells.next().unwrap_or_else(|| panic!("pin d0dd5693 number {name}")).contains("Some"))
        }).collect()
    }

    /// Names the pinned tables derive for one full grant. Profile allow forms select
    /// the rule rows. Launch names join every provider. Model essentials join `model`.
    fn lab_names(src: &str, profile: &str, provider: &str, arch: AuditArch) -> BTreeSet<String> {
        let arm = matches!(arch, AuditArch::Aarch64);
        let shared = raws(part(src, "const SHARED_RULES:"));
        let startup = raws(part(src, "const STARTUP_RULES:"));
        let at = src.find("const MODEL_ROOT_READ_RULE:").expect("pin d0dd5693 missing MODEL_ROOT_READ_RULE");
        let model_root = raws(src[at..].lines().next().unwrap())[0];
        let root = calls(part(src, "const ROOT_READ_SYSCALLS:"));
        let rows = number_rows(part(src, "const SECCOMP_SYSCALL_NUMBERS:"));
        assert!(rows.len() > 60, "pin d0dd5693 syscall numbers");
        let launch = calls(part(src, "const LAUNCH_ESSENTIALS:"));
        let model = calls(part(src, "const MODEL_RUNTIME_ESSENTIALS:"));
        let allowed = |call: &str| { let (_, x86, aarch64) = rows.iter().find(|(n, _, _)| *n == call).copied().unwrap_or_else(|| panic!("pin d0dd5693 has no number for {call}")); if arm { aarch64 } else { x86 } };
        let (mut known, mut set) = (BTreeSet::new(), BTreeSet::new());
        for entry in part(src, "const SECCOMP_RULE_SYSCALLS:").split("\n    (").skip(1) {
            let (head, rhs) = entry.split_once(',').unwrap_or_else(|| panic!("pin d0dd5693 rule entry"));
            let form = if head.contains("SHARED_RULES[0]") { shared[0] } else if head.contains("SHARED_RULES[1]") { shared[1] } else if head.contains("SHARED_RULES[2]") { shared[2] } else if head.contains("STARTUP_RULES[0]") { startup[0] } else if head.contains("STARTUP_RULES[1]") { startup[1] } else if head.contains("MODEL_ROOT_READ_RULE") { model_root } else { panic!("pin d0dd5693 rule key {head}") };
            known.insert(form);
            if !profile.lines().any(|line| line.trim() == form) { continue; }
            for call in if rhs.contains("ROOT_READ_SYSCALLS") && !rhs.contains("&[") { root.clone() } else { calls(rhs) } { if allowed(call) { set.insert(call.to_string()); } }
        }
        for call in launch { if allowed(call) { set.insert(call.to_string()); } }
        if provider == "model" { for call in model { if allowed(call) { set.insert(call.to_string()); } } }
        for line in profile.lines() { let form = line.trim(); if form.starts_with("(allow") && !known.contains(form) { panic!("pin d0dd5693 has no syscall row for {form}"); } }
        set
    }

    fn golden_names(text: &str) -> BTreeSet<String> {
        let lines: Vec<_> = text.lines().collect();
        let mut names = BTreeSet::new();
        for index in 0..lines.len().saturating_sub(1) {
            let (row, next) = (lines[index].trim(), lines[index + 1].trim());
            if !row.starts_with("0x0015") || !next.starts_with("0x0006") || !next.contains("0x7fff0000") { continue; }
            let Some(name) = row.split("# SYS_").nth(1).map(str::trim) else { continue };
            if ["clone", "clone3", "socketpair", "fcntl", "prlimit64", "futex", "socket"].contains(&name) { panic!("{name} is an argument-checked call, not an unconditional allow"); }
            names.insert(name.to_string());
        }
        names
    }

    /// Post-pin calls. Each row names the lab commit that added it. `did` has none.
    const LAB_BASELINE: &[(&str, AuditArch, &str, &str)] = &[
        ("wallet", AuditArch::X86_64, "rename", "51c503fe7"),
        ("wallet", AuditArch::Aarch64, "renameat", "51c503fe7"),
        ("model", AuditArch::X86_64, "rename", "6244ee894+b2451e091"),
        ("model", AuditArch::Aarch64, "renameat", "6244ee894+b2451e091"),
    ];

    fn slug(provider: RuntimeProviderId) -> &'static str {
        match provider { RuntimeProviderId::Did => "did", RuntimeProviderId::Wallet => "wallet", RuntimeProviderId::Model => "model", RuntimeProviderId::Localhost => "localhost", RuntimeProviderId::Object => "object", RuntimeProviderId::Chain => "chain" }
    }
    fn same_arch(left: AuditArch, right: AuditArch) -> bool {
        matches!((left, right), (AuditArch::X86_64, AuditArch::X86_64) | (AuditArch::Aarch64, AuditArch::Aarch64))
    }
    fn each_grant(mut body: impl FnMut(RuntimeProviderId, &str, AuditArch, &AdmittedRights, &str, &str)) {
        let src = pin("capsules/wallet-provider/tests/confine.rs");
        for provider in [RuntimeProviderId::Did, RuntimeProviderId::Wallet, RuntimeProviderId::Model] {
            let name = slug(provider);
            let profile = pin(&format!("capsules/{name}-provider/confine.sb"));
            let admitted = crate::provider::rights::admit_committed(provider);
            for arch in [AuditArch::X86_64, AuditArch::Aarch64] { body(provider, name, arch, &admitted, &src, &profile); }
        }
    }

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

    #[test]
    fn linux_names_match_the_pin_and_the_goldens() {
        each_grant(|provider, name, arch, admitted, src, profile| {
            let lab = lab_names(src, profile, name, arch);
            let full: BTreeSet<String> = linux_seccomp_list(provider, admitted, arch).into_iter().map(str::to_string).collect();
            let mut got = full.clone();
            let mut commits = String::new();
            for (who, row_arch, call, commit) in LAB_BASELINE {
                if *who == name && same_arch(*row_arch, arch) { got.remove(*call); commits.push_str(commit); commits.push(' '); }
            }
            if name == "model" {
                // Probe names are not in the lab pin. The test drops them before the comparison.
                for call in MODEL_PROBE_NAMES.split_whitespace() { got.remove(call); }
            }
            let (crate_only, pin_only): (Vec<_>, Vec<_>) = (got.difference(&lab).cloned().collect(), lab.difference(&got).cloned().collect());
            assert!(crate_only.is_empty() && pin_only.is_empty(), "{name} {arch:?} symmetric difference crate-only {crate_only:?} pin-only {pin_only:?} baseline {commits}");
            let arch_name = match arch { AuditArch::X86_64 => "x86_64", AuditArch::Aarch64 => "aarch64" };
            let golden_path = format!("{}/../../../capsules/wallet-provider/tests/{name}-seccomp-{arch_name}.golden", env!("CARGO_MANIFEST_DIR"));
            let golden = golden_names(&std::fs::read_to_string(&golden_path).unwrap_or_else(|err| panic!("{golden_path}: {err}")));
            let (crate_only, golden_only): (Vec<_>, Vec<_>) = (full.difference(&golden).cloned().collect(), golden.difference(&full).cloned().collect());
            assert!(crate_only.is_empty() && golden_only.is_empty(), "{name} {arch:?} golden symmetric difference crate-only {crate_only:?} golden-only {golden_only:?}");
        });
    }

    #[test]
    fn protocol_baseline_is_a_subset_of_the_pinned_grant() {
        each_grant(|provider, name, arch, admitted, src, profile| {
            let got = linux_seccomp_list(provider, admitted, arch);
            let lab = lab_names(src, profile, name, arch);
            for call in BASELINE.split_whitespace().filter(|call| number(call, arch).is_some()) {
                assert!(got.contains(&call), "{name} {arch:?} full grant is missing baseline {call}");
                assert!(lab.contains(call), "pin d0dd5693 does not derive baseline {call} for the {name} {arch:?} grant");
            }
        });
    }

    #[test]
    fn each_helper_keeps_its_own_measured_calls() {
        let local = crate::provider::rights::admit_runtime_grant(RuntimeProviderId::Localhost);
        let object = crate::provider::rights::admit_runtime_grant(RuntimeProviderId::Object);
        let chain = crate::provider::rights::admit_runtime_grant(RuntimeProviderId::Chain);
        let did = crate::provider::rights::admit_runtime_grant(RuntimeProviderId::Did);
        let local_x86 = linux_seccomp_list(RuntimeProviderId::Localhost, &local, AuditArch::X86_64);
        let object_x86 = linux_seccomp_list(RuntimeProviderId::Object, &object, AuditArch::X86_64);
        let chain_x86 = linux_seccomp_list(RuntimeProviderId::Chain, &chain, AuditArch::X86_64);
        let chain_arm = linux_seccomp_list(RuntimeProviderId::Chain, &chain, AuditArch::Aarch64);
        let did_x86 = linux_seccomp_list(RuntimeProviderId::Did, &did, AuditArch::X86_64);
        assert_ne!(chain_x86, did_x86, "chain keeps its own grant");
        for name in ["connect", "recvfrom", "sendmmsg", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd2", "exit", "rseq", "rt_sigprocmask", "rename"] {
            assert!(chain_x86.contains(&name), "chain x86_64 is missing {name}");
        }
        assert!(!chain_x86.contains(&"renameat"));
        assert!(chain_arm.contains(&"renameat") && chain_arm.contains(&"epoll_pwait"));
        assert!(!chain_arm.contains(&"rename") && !chain_arm.contains(&"epoll_wait"));
        for name in ["socket", "getsockopt", "sendto", "fcntl", "clone", "clone3", "setsockopt", "bind", "listen", "pipe2"] {
            assert!(!chain_x86.contains(&name) && !chain_arm.contains(&name), "{name} is not an unconditional chain allow");
            assert!(!local_x86.contains(&name) && !object_x86.contains(&name), "{name} leaked onto another helper");
        }
        assert!(!local_x86.contains(&"sendmmsg") && !object_x86.contains(&"sendmmsg"));
        assert!(local_x86.contains(&"rmdir"));
        assert!(local_x86.contains(&"readlink"), "x86_64 realpath uses syscall readlink");
        assert!(local_x86.contains(&"readlinkat"));
        assert!(!local_x86.contains(&"chmod"));
        assert!(!local_x86.contains(&"fchmodat"));
        assert!(!local_x86.contains(&"flock"));
        assert!(!local_x86.contains(&"socket"));
        assert!(!local_x86.contains(&"connect"));
        assert!(!chain_x86.contains(&"readlink"), "chain does not canonicalize");
        assert!(!chain_arm.contains(&"readlink"), "chain does not canonicalize");
        assert!(object_x86.contains(&"readlink"), "x86_64 realpath uses syscall readlink");
        assert!(object_x86.contains(&"readlinkat"));
        assert!(object_x86.contains(&"flock"));
        assert!(object_x86.contains(&"fchmod"), "mode uses fchmod on the held descriptor");
        assert!(!object_x86.contains(&"chmod"), "path chmod is not mediated by Landlock");
        assert!(!object_x86.contains(&"fchmodat"), "path chmod is not mediated by Landlock");
        assert!(object_x86.contains(&"rename"));
        assert!(object_x86.contains(&"rmdir"));
        assert!(!object_x86.contains(&"socket"));
        assert!(!object_x86.contains(&"clone"));
        let local_arm = linux_seccomp_list(RuntimeProviderId::Localhost, &local, AuditArch::Aarch64);
        let object_arm = linux_seccomp_list(RuntimeProviderId::Object, &object, AuditArch::Aarch64);
        assert!(!local_arm.contains(&"rmdir"));
        assert!(!local_arm.contains(&"readlink"), "aarch64 realpath uses readlinkat");
        assert!(local_arm.contains(&"readlinkat"));
        assert!(!local_arm.contains(&"chmod"));
        assert!(!local_arm.contains(&"fchmodat"));
        assert!(local_arm.contains(&"unlinkat"));
        assert!(!object_arm.contains(&"readlink"), "aarch64 realpath uses readlinkat");
        assert!(object_arm.contains(&"readlinkat"));
        assert!(object_arm.contains(&"flock"));
        assert!(object_arm.contains(&"fchmod"), "mode uses fchmod on the held descriptor");
        assert!(!object_arm.contains(&"fchmodat"), "path chmod is not mediated by Landlock");
        assert!(object_arm.contains(&"renameat"));
        assert!(!object_arm.contains(&"chmod"));
        assert!(!object_arm.contains(&"rename"));
        assert_ne!(object_x86, local_x86);
        assert_ne!(object_arm, local_arm);
    }
}
