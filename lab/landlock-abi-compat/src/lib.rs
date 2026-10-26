//! Landlock ABI decisions for the did, wallet, and model provider guards.
//!
//! This crate re-implements only the ABI choice from draft PRs #299 and #307.
//! It does not launch a provider. A decision is one of three outcomes: start
//! under the ruleset (`RunConfined`), refuse with a reason, or start while a
//! required right is missing (`RunWeaker`). The third outcome is the planted
//! best-effort path. The guards and the per-row rule never return it.

/// Lowest ABI both drafts accept. ABI 5 is the first that can deny device ioctl.
pub const GUARD_FLOOR_ABI: u32 = 5;

pub const FS_BASE_ABI: u32 = 1;
pub const REFER_ABI: u32 = 2;
pub const TRUNCATE_ABI: u32 = 3;
pub const NET_TCP_ABI: u32 = 4;
pub const IOCTL_DEV_ABI: u32 = 5;
pub const SCOPE_ABI: u32 = 6;

/// Filesystem and network bits from `<linux/landlock.h>`.
pub mod bits {
    pub const FS_EXECUTE: u64 = 1 << 0;
    pub const FS_WRITE_FILE: u64 = 1 << 1;
    pub const FS_READ_FILE: u64 = 1 << 2;
    pub const FS_READ_DIR: u64 = 1 << 3;
    pub const FS_REMOVE_DIR: u64 = 1 << 4;
    pub const FS_REMOVE_FILE: u64 = 1 << 5;
    pub const FS_MAKE_CHAR: u64 = 1 << 6;
    pub const FS_MAKE_DIR: u64 = 1 << 7;
    pub const FS_MAKE_REG: u64 = 1 << 8;
    pub const FS_MAKE_SOCK: u64 = 1 << 9;
    pub const FS_MAKE_FIFO: u64 = 1 << 10;
    pub const FS_MAKE_BLOCK: u64 = 1 << 11;
    pub const FS_MAKE_SYM: u64 = 1 << 12;
    pub const FS_REFER: u64 = 1 << 13;
    pub const FS_TRUNCATE: u64 = 1 << 14;
    pub const FS_IOCTL_DEV: u64 = 1 << 15;
    /// Every filesystem right ABI 5 defines (bits 0 through 15).
    pub const FS_ABI5_ALL: u64 = (1 << 16) - 1;
    /// ABI 1 rights only: bits 0 through 12. No REFER, TRUNCATE, or IOCTL_DEV.
    pub const FS_ABI1: u64 = (1 << 13) - 1;

    pub const NET_BIND_TCP: u64 = 1 << 0;
    pub const NET_CONNECT_TCP: u64 = 1 << 1;

    pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    pub const SCOPE_SIGNAL: u64 = 1 << 1;
}

/// What a host probe returned. `None` is ENOSYS or EOPNOTSUPP.
pub type Abi = Option<u32>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Start the provider under the ruleset this guard builds.
    RunConfined,
    /// Do not start the provider.
    Refuse { reason: String },
    /// Start the provider even though a required right is missing.
    RunWeaker { missing: Vec<&'static str> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Absence {
    /// Omitting the right leaves the action allowed. Starting is a weaker sandbox.
    Wider,
    /// Omitting the right leaves the action denied. Starting is stricter.
    Narrower,
    /// The right covers only part of the oracle row (TCP, not every socket family).
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feature {
    pub abi: u32,
    pub kernel: &'static str,
    pub commit: &'static str,
    pub name: &'static str,
    pub absence: Absence,
}

/// One wider-if-missing right the storage and outside-write rows need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredRight {
    pub name: &'static str,
    pub minimum_abi: u32,
    pub row: &'static str,
}

/// Rights whose absence makes the sandbox wider than the oracle.
///
/// REFER is not here. The kernel denies reparenting when that right is absent,
/// which is narrower. Network TCP and scope are not here either: TCP does not
/// cover `(deny network*)`, and neither draft sets a scope bit.
pub const REQUIRED_WIDER_RIGHTS: &[RequiredRight] = &[
    RequiredRight {
        name: "filesystem rights",
        minimum_abi: FS_BASE_ABI,
        row: "exec of PROVIDER_EXECUTABLE, storage read/write, outside read/write",
    },
    RequiredRight {
        name: "TRUNCATE",
        minimum_abi: TRUNCATE_ABI,
        row: "outside truncate, and O_TRUNC only under STORAGE_ROOT",
    },
    RequiredRight {
        name: "IOCTL_DEV",
        minimum_abi: IOCTL_DEV_ABI,
        row: "ioctl on a newly opened character or block device",
    },
];

/// ABI 1..6, in order. Kernel versions and commits are the Landlock releases.
pub fn features() -> &'static [Feature] {
    &[
        Feature {
            abi: 1,
            kernel: "5.13",
            commit: "17ae69aba89dbfa2139b7f8024b757ab3cc42f59",
            name: "filesystem rights",
            absence: Absence::Wider,
        },
        Feature {
            abi: 2,
            kernel: "5.19",
            commit: "cb44e4f061e16be65b8a16505e121490c66d30d0",
            name: "REFER",
            absence: Absence::Narrower,
        },
        Feature {
            abi: 3,
            kernel: "6.2",
            commit: "299e2b1967578b1442128ba8b3e86ed3427d3651",
            name: "TRUNCATE",
            absence: Absence::Wider,
        },
        Feature {
            abi: 4,
            kernel: "6.7",
            commit: "136cc1e1f5be75f57f1e0404b94ee1c8792cb07d",
            name: "TCP bind and connect",
            absence: Absence::Partial,
        },
        Feature {
            abi: 5,
            kernel: "6.10",
            commit: "2fc0e7892c10734c1b7c613ef04836d57d4676d5",
            name: "IOCTL_DEV",
            absence: Absence::Wider,
        },
        Feature {
            abi: 6,
            kernel: "6.12",
            commit: "e1b061b444fb01c237838f0d8238653afe6a8094",
            name: "abstract unix scope and signal scope",
            absence: Absence::Wider,
        },
    ]
}

pub fn missing_required(abi: Abi) -> Vec<&'static RequiredRight> {
    let have = abi.unwrap_or(0);
    REQUIRED_WIDER_RIGHTS
        .iter()
        .filter(|right| have < right.minimum_abi)
        .collect()
}

/// #299 (`cursor/fail-closed-linux-recover`): refuse below ABI 5.
///
/// The floor cannot be lowered. A probe failure and an old ABI are different
/// reasons. At ABI 5 and above the guard runs, including on a kernel that has
/// scope bits it does not set.
pub fn decide_guard_299(abi: Abi) -> Decision {
    match abi {
        None => Decision::Refuse {
            reason: "the kernel has no Landlock".to_string(),
        },
        Some(found) if found < GUARD_FLOOR_ABI => Decision::Refuse {
            reason: format!(
                "the Landlock ABI cannot express the STORAGE_ROOT row (needs ABI {GUARD_FLOOR_ABI}, this kernel reports ABI {found})"
            ),
        },
        Some(_) => Decision::RunConfined,
    }
}

/// #307 (`cursor/fail-closed-linux-0b95`): the same floor, its own reason text.
pub fn decide_guard_307(abi: Abi) -> Decision {
    match abi {
        None => Decision::Refuse {
            reason: "Landlock is not available".to_string(),
        },
        Some(found) if found < GUARD_FLOOR_ABI => Decision::Refuse {
            reason: format!("Landlock ABI {found} is below the required {GUARD_FLOOR_ABI}"),
        },
        Some(_) => Decision::RunConfined,
    }
}

/// Option (b): refuse only for a wider-if-missing right, and name that right.
///
/// REFER does not cause a refusal. ABI 4 refuses for IOCTL_DEV alone. ABI 1
/// and 2 refuse for TRUNCATE and IOCTL_DEV. The outcome on a real ABI number
/// below 5 is still a refusal, with a different reason than the hard floor.
pub fn decide_per_row(abi: Abi) -> Decision {
    let missing = missing_required(abi);
    if missing.is_empty() {
        Decision::RunConfined
    } else {
        Decision::Refuse {
            reason: format!("the Landlock ABI cannot express {}", join_names(&missing)),
        }
    }
}

/// Option (a): one hard floor. This is what both drafts do.
pub fn decide_hard_floor(abi: Abi) -> Decision {
    decide_guard_307(abi)
}

/// The dangerous case, copied from the kernel's best-effort sample: drop every
/// right the ABI lacks and start anyway. A missing Landlock starts too.
pub fn decide_best_effort(abi: Abi) -> Decision {
    let missing = missing_required(abi);
    if missing.is_empty() {
        Decision::RunConfined
    } else {
        Decision::RunWeaker {
            missing: missing.iter().map(|right| right.name).collect(),
        }
    }
}

/// True when a decision starts the provider while a required right is absent.
pub fn is_silently_weaker(decision: &Decision, abi: Abi) -> bool {
    match decision {
        Decision::RunWeaker { .. } => true,
        Decision::Refuse { .. } => false,
        Decision::RunConfined => !missing_required(abi).is_empty(),
    }
}

/// Compensating controls for option (c). Each flag is a control the launch
/// actually applied. A `false` flag is a missing control, and the start refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controls {
    /// Host files are not reachable by path in this mount namespace.
    pub mount_namespace_hides_host_files: bool,
    /// Inherited descriptors other than the protocol pipes are closed.
    pub inherited_descriptors_closed: bool,
    /// The launch checked that `STORAGE_ROOT` holds no character or block device.
    pub storage_root_has_no_device_node: bool,
    /// Seccomp returns EPERM for `socket` and `socketpair`.
    pub seccomp_denies_socket: bool,
}

impl Controls {
    pub const NONE: Controls = Controls {
        mount_namespace_hides_host_files: false,
        inherited_descriptors_closed: false,
        storage_root_has_no_device_node: false,
        seccomp_denies_socket: false,
    };

    /// Every control option (c) uses in place of a missing Landlock right.
    pub const ALL: Controls = Controls {
        mount_namespace_hides_host_files: true,
        inherited_descriptors_closed: true,
        storage_root_has_no_device_node: true,
        seccomp_denies_socket: true,
    };
}

/// Option (c). Landlock rights that are present are used. Each missing wider
/// right needs its control. `(deny network*)` needs the seccomp socket denial
/// at every ABI, because Landlock TCP rights do not cover that row.
pub fn decide_compensated(abi: Abi, controls: Controls) -> Decision {
    let mut holes: Vec<&str> = Vec::new();
    let have = abi.unwrap_or(0);
    if have < FS_BASE_ABI
        && !(controls.mount_namespace_hides_host_files && controls.inherited_descriptors_closed)
    {
        holes.push("filesystem rights");
    }
    if have < TRUNCATE_ABI
        && !(controls.mount_namespace_hides_host_files && controls.inherited_descriptors_closed)
    {
        holes.push("TRUNCATE");
    }
    if have < IOCTL_DEV_ABI
        && !(controls.storage_root_has_no_device_node
            && controls.mount_namespace_hides_host_files
            && controls.inherited_descriptors_closed)
    {
        holes.push("IOCTL_DEV");
    }
    if !controls.seccomp_denies_socket {
        holes.push("network");
    }
    if holes.is_empty() {
        Decision::RunConfined
    } else {
        Decision::Refuse {
            reason: format!("missing required confinement: {}", holes.join(", ")),
        }
    }
}

/// The ruleset each draft installs once it has decided to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchedRuleset {
    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
    pub executable: u64,
    pub storage: u64,
}

/// #299 `FsRules::read_write_dir`: every ABI 5 filesystem right except execute.
/// The ruleset attribute has no network field and no scope field.
pub fn ruleset_299() -> LaunchedRuleset {
    LaunchedRuleset {
        handled_fs: bits::FS_ABI5_ALL,
        handled_net: 0,
        scoped: 0,
        executable: bits::FS_EXECUTE | bits::FS_READ_FILE,
        storage: bits::FS_ABI5_ALL & !bits::FS_EXECUTE,
    }
}

/// #307 storage mask: read, write, truncate, make and remove of regular files
/// and directories. TCP bind and connect are handled and not granted. Scope is
/// not set.
pub fn ruleset_307() -> LaunchedRuleset {
    LaunchedRuleset {
        handled_fs: bits::FS_ABI5_ALL,
        handled_net: bits::NET_BIND_TCP | bits::NET_CONNECT_TCP,
        scoped: 0,
        executable: bits::FS_EXECUTE | bits::FS_READ_FILE,
        storage: bits::FS_READ_FILE
            | bits::FS_READ_DIR
            | bits::FS_WRITE_FILE
            | bits::FS_TRUNCATE
            | bits::FS_MAKE_REG
            | bits::FS_MAKE_DIR
            | bits::FS_REMOVE_FILE
            | bits::FS_REMOVE_DIR,
    }
}

/// Landlock ABI 1..6 does not express `(deny network*)`. The row is TCP only
/// from ABI 4, and UDP, Unix, and the other families stay out of the ruleset.
pub fn landlock_expresses_deny_network(_abi: Abi) -> bool {
    false
}

/// Neither draft sets `LANDLOCK_SCOPE_SIGNAL` or creates a PID namespace.
pub fn signal_row_confined(pid_namespace: bool, scope_signal: bool) -> bool {
    pid_namespace || scope_signal
}

fn join_names(rights: &[&RequiredRight]) -> String {
    rights
        .iter()
        .map(|right| format!("{} ({})", right.name, right.row))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod floor_tests {
    use super::*;

    #[test]
    fn refer_is_not_a_required_right() {
        assert!(REQUIRED_WIDER_RIGHTS
            .iter()
            .all(|right| right.name != "REFER"));
        assert_eq!(
            features()
                .iter()
                .find(|feature| feature.name == "REFER")
                .map(|feature| feature.absence),
            Some(Absence::Narrower)
        );
    }

    #[test]
    fn features_are_abi_1_through_6() {
        let abis: Vec<u32> = features().iter().map(|feature| feature.abi).collect();
        assert_eq!(abis, vec![1, 2, 3, 4, 5, 6]);
        for feature in features() {
            assert_eq!(feature.commit.len(), 40);
            assert!(feature.commit.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
