//! Lab-only policy model for the #307 Landlock floor and the proposed
//! rights probe. It does not talk to a real kernel. It exists so this
//! review can show that today's guard trusts a reported ABI number.

/// First ABI that can deny file truncation.
pub const TRUNCATE_ABI: u32 = 3;
/// First ABI that can deny device ioctl.
pub const IOCTL_DEV_ABI: u32 = 5;

pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// Filesystem bits ABI 1 can handle (no REFER, no TRUNCATE, no IOCTL_DEV).
pub const ABI1_FS: u64 = (1u64 << 13) - 1;

pub const MISSING_TRUNCATE: i32 = 1;
pub const MISSING_IOCTL_DEV: i32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeededRight {
    pub name: &'static str,
    pub minimum_abi: u32,
    pub mask: i32,
    pub access: u64,
}

pub const FILE_PROFILE_NEEDED_RIGHTS: &[NeededRight] = &[
    NeededRight {
        name: "truncate",
        minimum_abi: TRUNCATE_ABI,
        mask: MISSING_TRUNCATE,
        access: ACCESS_FS_TRUNCATE,
    },
    NeededRight {
        name: "ioctl_dev",
        minimum_abi: IOCTL_DEV_ABI,
        mask: MISSING_IOCTL_DEV,
        access: ACCESS_FS_IOCTL_DEV,
    },
];

/// A kernel that can lie: the version query and the rights it will
/// actually accept in `landlock_create_ruleset` need not match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelRights {
    pub reported_abi: u32,
    /// Bits `landlock_create_ruleset` will accept. Unknown bits give EINVAL.
    pub accepted_fs: u64,
}

/// #307's launch gate: only the reported ABI number.
pub fn missing_required_mask(abi: u32) -> Option<i32> {
    let mut mask = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        if abi < right.minimum_abi {
            mask |= right.mask;
        }
    }
    (mask != 0).then_some(mask)
}

pub fn current_launches_on_reported_abi(abi: u32) -> bool {
    missing_required_mask(abi).is_none()
}

/// Today's confine() uses `missing_required_mask(reported)` and never
/// asks whether `create_ruleset` accepts each needed bit.
pub fn current_guard_launches(kernel: &KernelRights) -> bool {
    current_launches_on_reported_abi(kernel.reported_abi)
}

/// Proposed probe: try each needed right. EINVAL means the kernel does
/// not have that right, whatever number the version query printed.
pub fn probe_needed_rights(kernel: &KernelRights) -> Result<(), String> {
    let mut missing = Vec::new();
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        if kernel.accepted_fs & right.access != right.access {
            missing.push(format!(
                "{}: landlock_create_ruleset returned EINVAL (reported ABI {})",
                right.name, kernel.reported_abi
            ));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("this kernel cannot deny {}", missing.join("; ")))
    }
}

/// Patched launch gate: the ABI-number check stays as a fast path for
/// honest old kernels. The probe is what decides on a liar.
pub fn patched_guard_launches(kernel: &KernelRights) -> bool {
    current_launches_on_reported_abi(kernel.reported_abi) && probe_needed_rights(kernel).is_ok()
}

/// Claims ABI 5 (ioctl_dev exists) but only accepts ABI 1 filesystem bits.
pub fn lying_abi5_with_abi1_rights() -> KernelRights {
    KernelRights {
        reported_abi: 5,
        accepted_fs: ABI1_FS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_abi_table_matches_307() {
        assert_eq!(
            missing_required_mask(1),
            Some(MISSING_TRUNCATE | MISSING_IOCTL_DEV)
        );
        assert_eq!(missing_required_mask(4), Some(MISSING_IOCTL_DEV));
        assert_eq!(missing_required_mask(5), None);
        assert_eq!(missing_required_mask(6), None);
        assert!(current_launches_on_reported_abi(5));
        assert!(!current_launches_on_reported_abi(4));
    }

    #[test]
    fn current_code_launches_on_a_lying_abi5_kernel() {
        let kernel = lying_abi5_with_abi1_rights();
        assert!(
            current_guard_launches(&kernel),
            "today's floor trusts reported ABI 5 and does not look at accepted_fs"
        );
        assert_eq!(kernel.accepted_fs & ACCESS_FS_TRUNCATE, 0);
        assert_eq!(kernel.accepted_fs & ACCESS_FS_IOCTL_DEV, 0);
    }

    #[test]
    fn patched_code_refuses_a_lying_abi5_kernel() {
        let kernel = lying_abi5_with_abi1_rights();
        assert!(!patched_guard_launches(&kernel));
        let reason = probe_needed_rights(&kernel).expect_err("liar must fail the probe");
        assert!(reason.contains("cannot deny truncate"), "{reason}");
        assert!(
            reason.contains("landlock_create_ruleset returned EINVAL"),
            "{reason}"
        );
        assert!(reason.contains("reported ABI 5"), "{reason}");
        assert!(reason.contains("ioctl_dev"), "{reason}");
    }

    #[test]
    fn honest_abi5_still_launches_after_the_probe() {
        let kernel = KernelRights {
            reported_abi: 5,
            accepted_fs: ABI1_FS | ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV,
        };
        assert!(current_guard_launches(&kernel));
        assert!(patched_guard_launches(&kernel));
        assert!(probe_needed_rights(&kernel).is_ok());
    }

    #[test]
    fn honest_abi1_refuses_on_both() {
        let kernel = KernelRights {
            reported_abi: 1,
            accepted_fs: ABI1_FS,
        };
        assert!(!current_guard_launches(&kernel));
        assert!(!patched_guard_launches(&kernel));
    }
}
