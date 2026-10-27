//! Fail-closed provider launch guard for Linux (M1 C0 lab).
//!
//! The guard runs after fork and before exec. It applies six layers in this
//! order: user namespace, PID namespace, capability drop, no_new_privs,
//! seccomp, Landlock. Landlock uses a per-right floor, then try-creates a
//! ruleset for each needed right so a lying ABI number cannot hide a missing
//! bit (`EINVAL` is a named refusal). The process `launch` returns is the
//! PID-namespace init. The helper that unshares the namespace exits as soon
//! as it hands init's host pid back. Init reaps every child (`waitpid(-1)`),
//! and SIGKILL or SIGTERM of that pid takes the namespace down. A start
//! needs two things: EOF on the close-on-exec fault pipe, and
//! `/proc/<provider pid>/exe` matching the expected binary (device and
//! inode). Closing that pipe without `execve` is a refusal. The identity
//! pipe stays close-on-exec. A static binary that writes nothing is
//! accepted when that identity matches. After
//! `landlock_restrict_self` a throwaway child tries one denied operation
//! per needed right; any success is a refusal. Before restrict, a terminal
//! or a socket on fd 0, 1 or 2 is replaced with `/dev/null`; a failed
//! replace refuses and names the fd. After the maps and the capability
//! drop, the guard makes the granted binary execute-only and the
//! provider sets `PR_SET_DUMPABLE` to 0 in `exec()`, so `execve` does
//! not reset dumpable to 1. The first seccomp filter then allows
//! `PR_SET_DUMPABLE` only with value 0, and denies `pidfd_open`,
//! `pidfd_getfd` and `pidfd_send_signal`. Same-uid host
//! `process_vm_readv`, `pidfd_getfd` and `perf_event_open` stay NOT
//! CLOSED on a 1:1 userns. After confine the guard installs a
//! second seccomp filter that returns EPERM for every `execveat` and for
//! every `execve` except the helper's granted-path pointer. That one
//! `execve` is the confined program's own initial exec. After that image
//! starts, pathname re-exec of the granted binary and
//! `execve("/proc/self/fd/N")` of a memfd both return EPERM. If the
//! install fails, launch refuses (`install_no_exec`). Before exec the
//! guard closes every fd except stdin, stdout, stderr and the fault pipe.
//! The identity pipe stays close-on-exec. Any bytes on the fault pipe,
//! including a `ConfineReady` record without `execve`, are a refusal.
//! `launch` has no unconfined path.

pub mod real;
pub mod seccomp;
pub mod sim;

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Exit code of `fcl-launch` when the guard refuses (`EX_OSERR`).
pub const REFUSAL_EXIT_CODE: i32 = 71;

/// An OS error number, as the kernel returned it.
pub type Errno = i32;

/// First Landlock ABI that can deny file truncation.
pub const TRUNCATE_ABI: u32 = 3;
/// First Landlock ABI that can deny device ioctl.
pub const IOCTL_DEV_ABI: u32 = 5;
/// First Landlock ABI that can set `LANDLOCK_SCOPE_SIGNAL`.
pub const SCOPE_SIGNAL_ABI: u32 = 6;

/// Reason prefix when `unshare(CLONE_NEWPID)` fails. The OS error follows.
pub const PID_NAMESPACE_UNAVAILABLE: &str = "the PID namespace cannot be created";

/// Bit in `Fault.errno` when `Step::AbiFloor` names a missing `truncate`.
pub const MISSING_TRUNCATE: i32 = 1;
/// Bit in `Fault.errno` when `Step::AbiFloor` names a missing `ioctl_dev`.
pub const MISSING_IOCTL_DEV: i32 = 2;
/// Bit in `Fault.errno` when a test-only extra right is missing.
///
/// Production `FILE_PROFILE_NEEDED_RIGHTS` does not include this bit.
/// `ProviderSpec::require_test_right` and the `FCL_TEST_HOOKS` CLI switch
/// add it so a real ABI 6 host can still refuse on the per-right path.
pub const MISSING_TEST_FUTURE_FS: i32 = 4;
/// Name of the test-only extra right. No current Landlock ABI expresses it.
pub const TEST_FUTURE_FS_NAME: &str = "future_fs";
/// First ABI that would express the test-only extra right. Above ABI 6.
pub const TEST_FUTURE_FS_ABI: u32 = 7;
/// `Fault.found` when `Step::Report` names an empty fault pipe.
pub const EMPTY_PIPE_FOUND: u32 = 1;
/// `Fault.found` when the running image is not the expected executable.
pub const EXEC_IDENTITY_FOUND: u32 = 2;
/// Errno when a Landlock right was accepted and then ignored.
pub const ENFORCEMENT_BROKEN: Errno = libc::EBADE;

/// Landlock values from `<linux/landlock.h>`.
pub mod landlock {
    pub const CREATE_RULESET_VERSION: u32 = 1 << 0;
    pub const RULE_PATH_BENEATH: u32 = 1;

    pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
    pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
    pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    pub const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    pub const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    pub const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    pub const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    pub const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    pub const ACCESS_FS_REFER: u64 = 1 << 13;
    pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    pub const SCOPE_SIGNAL: u64 = 1 << 1;

    /// Every filesystem right ABI 5 defines, bit 0 to `ACCESS_FS_IOCTL_DEV`.
    pub const HANDLED_FS: u64 = (ACCESS_FS_IOCTL_DEV << 1) - 1;
    pub const HANDLED_NET: u64 = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;

    /// The eight storage rights this lab grants. No `REFER`, no `IOCTL_DEV`,
    /// and no create of char, sock, fifo, block, or symlink.
    pub const STORAGE_ROOT_ACCESS: u64 = ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_TRUNCATE
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_REMOVE_DIR;
    /// Linux `execve` opens the binary for read and execute.
    pub const EXECUTABLE_ACCESS: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE;
}

/// One wider-if-missing right the shared file profile needs.
///
/// `did-provider`, `wallet-provider` and `model-provider` share this list.
/// `REFER` is not here: the kernel already denies reparent when that bit is
/// absent. TCP bind/connect and `LANDLOCK_SCOPE_SIGNAL` are not here either:
/// seccomp already denies `socket`, and scope is applied only when ABI 6
/// reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeededRight {
    pub name: &'static str,
    pub minimum_abi: u32,
    pub mask: i32,
    /// Landlock filesystem bit to try-create. Used by the rights probe.
    pub access: u64,
}

/// Rights whose absence leaves the sandbox wider than `(deny default)`.
pub const FILE_PROFILE_NEEDED_RIGHTS: &[NeededRight] = &[
    NeededRight {
        name: "truncate",
        minimum_abi: TRUNCATE_ABI,
        mask: MISSING_TRUNCATE,
        access: landlock::ACCESS_FS_TRUNCATE,
    },
    NeededRight {
        name: "ioctl_dev",
        minimum_abi: IOCTL_DEV_ABI,
        mask: MISSING_IOCTL_DEV,
        access: landlock::ACCESS_FS_IOCTL_DEV,
    },
];

/// Filesystem bits this ABI can handle. Unknown bits are omitted so
/// `landlock_create_ruleset` does not see `EINVAL`.
pub fn handled_fs_for_abi(abi: u32) -> u64 {
    let mut fs = (1u64 << 13) - 1;
    if abi >= 2 {
        fs |= landlock::ACCESS_FS_REFER;
    }
    if abi >= 3 {
        fs |= landlock::ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        fs |= landlock::ACCESS_FS_IOCTL_DEV;
    }
    fs
}

/// TCP bind and connect, from ABI 4. Not a launch requirement: seccomp
/// already denies `socket`.
pub fn handled_net_for_abi(abi: u32) -> u64 {
    if abi >= 4 {
        landlock::HANDLED_NET
    } else {
        0
    }
}

/// `LANDLOCK_SCOPE_SIGNAL` from ABI 6. Below that the bit does not exist.
pub fn scoped_for_abi(abi: u32) -> u64 {
    if abi >= SCOPE_SIGNAL_ABI {
        landlock::SCOPE_SIGNAL
    } else {
        0
    }
}

/// Attribute size `landlock_create_ruleset` should receive. ABI 1-3 know
/// only the filesystem field, ABI 4-5 add net, ABI 6 adds scope.
pub fn ruleset_attr_size(handled_net: u64, scoped: u64) -> usize {
    if scoped != 0 {
        24
    } else if handled_net != 0 {
        16
    } else {
        8
    }
}

/// Mask of needed rights this ABI cannot express. `None` means every
/// needed right is present; the guard must not drop a bit from the mask.
pub fn missing_required_mask(abi: u32) -> Option<i32> {
    missing_required_mask_with(abi, 0)
}

/// Like `missing_required_mask`, plus any test-only extra bits in `extra`.
/// Extra bits can only add a refusal. They cannot drop a file-profile right.
pub fn missing_required_mask_with(abi: u32, extra: i32) -> Option<i32> {
    let mut mask = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        if abi < right.minimum_abi {
            mask |= right.mask;
        }
    }
    if extra & MISSING_TEST_FUTURE_FS != 0 && abi < TEST_FUTURE_FS_ABI {
        mask |= MISSING_TEST_FUTURE_FS;
    }
    (mask != 0).then_some(mask)
}

/// Reason text for a missing-right refusal. Names each right and the ABI
/// that first expresses it.
pub fn missing_rights_reason(abi: u32, mask: i32) -> String {
    let mut names: Vec<String> = FILE_PROFILE_NEEDED_RIGHTS
        .iter()
        .filter(|right| mask & right.mask != 0)
        .map(|right| format!("{} (needs ABI {})", right.name, right.minimum_abi))
        .collect();
    if mask & MISSING_TEST_FUTURE_FS != 0 {
        names.push(format!(
            "{TEST_FUTURE_FS_NAME} (needs ABI {TEST_FUTURE_FS_ABI})"
        ));
    }
    format!(
        "this kernel's Landlock ABI {abi} cannot deny {}",
        names.join("; ")
    )
}

/// Whether this ABI would start the shared file-profile providers.
pub fn file_profile_launches_on_abi(abi: u32) -> bool {
    missing_required_mask(abi).is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    UserNamespace,
    PidNamespace,
    Capabilities,
    NoNewPrivs,
    Seccomp,
    Landlock,
    Exec,
    Launch,
}

impl Layer {
    pub fn name(self) -> &'static str {
        match self {
            Layer::UserNamespace => "user-namespace",
            Layer::PidNamespace => "pid-namespace",
            Layer::Capabilities => "capabilities",
            Layer::NoNewPrivs => "no_new_privs",
            Layer::Seccomp => "seccomp",
            Layer::Landlock => "landlock",
            Layer::Exec => "exec",
            Layer::Launch => "launch",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Step {
    Unshare = 1,
    UidMap,
    Setgroups,
    GidMap,
    UnsharePid,
    LastCapability,
    BoundingSet,
    AmbientSet,
    CapabilitySets,
    SetNoNewPrivs,
    SetDumpable,
    InstallFilter,
    AbiProbe,
    AbiFloor,
    RightProbe,
    CreateRuleset,
    StorageRootRule,
    ExecutableRule,
    RestrictSelf,
    CloseFds,
    EnforceSelf,
    Execve,
    Prepare,
    Pipe,
    Fork,
    PidFork,
    Report,
    ConfineReady,
    ExecIdentity,
    SanitizeStdio,
    InstallNoExec,
}

impl Step {
    /// The steps that run in the provider's process, in guard order.
    pub const GUARD: [Step; 24] = [
        Step::Unshare,
        Step::UidMap,
        Step::Setgroups,
        Step::GidMap,
        Step::UnsharePid,
        Step::LastCapability,
        Step::BoundingSet,
        Step::AmbientSet,
        Step::CapabilitySets,
        Step::SetNoNewPrivs,
        Step::SetDumpable,
        Step::InstallFilter,
        Step::AbiProbe,
        Step::AbiFloor,
        Step::RightProbe,
        Step::CreateRuleset,
        Step::StorageRootRule,
        Step::ExecutableRule,
        Step::SanitizeStdio,
        Step::RestrictSelf,
        Step::CloseFds,
        Step::InstallNoExec,
        Step::EnforceSelf,
        Step::Execve,
    ];
    const LAUNCH: [Step; 7] = [
        Step::Prepare,
        Step::Pipe,
        Step::Fork,
        Step::PidFork,
        Step::Report,
        Step::ConfineReady,
        Step::ExecIdentity,
    ];

    pub fn layer(self) -> Layer {
        match self {
            Step::Unshare | Step::UidMap | Step::Setgroups | Step::GidMap => Layer::UserNamespace,
            Step::UnsharePid | Step::PidFork => Layer::PidNamespace,
            Step::LastCapability | Step::BoundingSet | Step::AmbientSet | Step::CapabilitySets => {
                Layer::Capabilities
            }
            Step::SetNoNewPrivs | Step::SetDumpable => Layer::NoNewPrivs,
            Step::InstallFilter | Step::InstallNoExec => Layer::Seccomp,
            Step::AbiProbe
            | Step::AbiFloor
            | Step::RightProbe
            | Step::CreateRuleset
            | Step::StorageRootRule
            | Step::ExecutableRule
            | Step::RestrictSelf
            | Step::EnforceSelf => Layer::Landlock,
            Step::Execve => Layer::Exec,
            Step::Prepare
            | Step::Pipe
            | Step::Fork
            | Step::Report
            | Step::ConfineReady
            | Step::CloseFds
            | Step::ExecIdentity
            | Step::SanitizeStdio => Layer::Launch,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Step::Unshare => "unshare",
            Step::UidMap => "uid_map",
            Step::Setgroups => "setgroups",
            Step::GidMap => "gid_map",
            Step::UnsharePid => "unshare_pid",
            Step::LastCapability => "cap_last_cap",
            Step::BoundingSet => "bounding_set",
            Step::AmbientSet => "ambient_set",
            Step::CapabilitySets => "capset",
            Step::SetNoNewPrivs => "set_no_new_privs",
            Step::SetDumpable => "set_dumpable",
            Step::InstallFilter => "install_filter",
            Step::AbiProbe => "abi_probe",
            Step::AbiFloor => "abi_floor",
            Step::RightProbe => "right_probe",
            Step::CreateRuleset => "create_ruleset",
            Step::StorageRootRule => "storage_root_rule",
            Step::ExecutableRule => "executable_rule",
            Step::RestrictSelf => "restrict_self",
            Step::CloseFds => "close_fds",
            Step::EnforceSelf => "enforce_self",
            Step::Execve => "execve",
            Step::Prepare => "prepare",
            Step::Pipe => "pipe",
            Step::Fork => "fork",
            Step::PidFork => "pid_fork",
            Step::Report => "report",
            Step::ConfineReady => "confine_ready",
            Step::ExecIdentity => "exec_identity",
            Step::SanitizeStdio => "sanitize_stdio",
            Step::InstallNoExec => "install_no_exec",
        }
    }

    fn from_code(code: u32) -> Option<Step> {
        Step::GUARD
            .iter()
            .chain(Step::LAUNCH.iter())
            .copied()
            .find(|step| *step as u32 == code)
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the guard reports from the provider's process. Plain data, so it can
/// cross from the forked child to the parent without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub step: Step,
    /// 0 when the step has no OS error (`Step::AbiFloor`).
    pub errno: Errno,
    /// The host's Landlock ABI, for `Step::AbiFloor`.
    pub found: u32,
}

impl Fault {
    pub const ENCODED_LEN: usize = 12;

    pub const fn os(step: Step, errno: Errno) -> Fault {
        Fault {
            step,
            errno,
            found: 0,
        }
    }

    pub const fn abi_floor(found: u32) -> Fault {
        Fault {
            step: Step::AbiFloor,
            errno: 0,
            found,
        }
    }

    pub const fn missing_rights(found: u32, mask: i32) -> Fault {
        Fault {
            step: Step::AbiFloor,
            errno: mask,
            found,
        }
    }

    pub const fn right_probe(found: u32, mask: i32) -> Fault {
        Fault {
            step: Step::RightProbe,
            errno: mask,
            found,
        }
    }

    /// A ready record without `execve`. The parent treats any bytes as a
    /// fault, so this record is a refusal, not a start.
    pub const fn confine_ready() -> Fault {
        Fault {
            step: Step::ConfineReady,
            errno: 0,
            found: 0,
        }
    }

    /// The child ended without writing a ready record or a refusal.
    pub const fn empty_pipe() -> Fault {
        Fault {
            step: Step::Report,
            errno: libc::EPIPE,
            found: EMPTY_PIPE_FOUND,
        }
    }

    /// EOF on the fault pipe, but `/proc/<pid>/exe` is not the expected binary.
    pub const fn exec_identity() -> Fault {
        Fault {
            step: Step::ExecIdentity,
            errno: libc::ENOEXEC,
            found: EXEC_IDENTITY_FOUND,
        }
    }

    /// A needed Landlock right was accepted and then ignored.
    pub const fn enforce_broken() -> Fault {
        Fault {
            step: Step::EnforceSelf,
            errno: ENFORCEMENT_BROKEN,
            found: 0,
        }
    }

    pub fn encode(self) -> [u8; Fault::ENCODED_LEN] {
        let mut bytes = [0u8; Fault::ENCODED_LEN];
        bytes[0..4].copy_from_slice(&(self.step as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&self.errno.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.found.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Fault> {
        let bytes: &[u8; Fault::ENCODED_LEN] = bytes.try_into().ok()?;
        let word = |at: usize| [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        Some(Fault {
            step: Step::from_code(u32::from_le_bytes(word(0)))?,
            errno: i32::from_le_bytes(word(4)),
            found: u32::from_le_bytes(word(8)),
        })
    }
}

/// Why a provider was not started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub provider: String,
    pub layer: Layer,
    pub step: Step,
    pub errno: Option<Errno>,
    pub reason: String,
}

impl Refusal {
    pub fn new(provider: &str, fault: Fault, landlock_abi_floor: u32) -> Refusal {
        let reason = match fault.step {
            Step::AbiFloor if fault.errno == 0 => format!(
                "Landlock ABI {} is below the required {}",
                fault.found, landlock_abi_floor
            ),
            Step::AbiFloor => {
                let rights = missing_rights_reason(fault.found, fault.errno);
                if fault.found < landlock_abi_floor {
                    format!(
                        "{rights}; Landlock ABI {} is below the required {}",
                        fault.found, landlock_abi_floor
                    )
                } else {
                    rights
                }
            }
            Step::RightProbe if fault.found != 0 => format!(
                "{}: landlock_create_ruleset returned EINVAL (reported ABI {})",
                missing_rights_reason(fault.found, fault.errno),
                fault.found
            ),
            Step::ConfineReady => "ConfineReady without execve is not a start".to_string(),
            Step::ExecIdentity => "the running image is not the expected executable".to_string(),
            Step::EnforceSelf => "Landlock accepted a right and did not enforce it".to_string(),
            Step::SanitizeStdio => format!(
                "fd {} is a terminal or a socket and could not be replaced: {}",
                fault.found,
                io::Error::from_raw_os_error(fault.errno)
            ),
            Step::InstallNoExec => format!(
                "the no-exec seccomp filter could not be installed: {}",
                io::Error::from_raw_os_error(fault.errno)
            ),
            Step::AbiProbe => format!(
                "Landlock is not available: {}",
                io::Error::from_raw_os_error(fault.errno)
            ),
            Step::UnsharePid => format!(
                "{PID_NAMESPACE_UNAVAILABLE}: {}",
                io::Error::from_raw_os_error(fault.errno)
            ),
            Step::Report if fault.found == EMPTY_PIPE_FOUND => {
                "the child ended before it wrote a fault or started".to_string()
            }
            _ => io::Error::from_raw_os_error(fault.errno).to_string(),
        };
        Refusal {
            provider: provider.to_string(),
            layer: fault.step.layer(),
            step: fault.step,
            errno: (fault.step != Step::AbiFloor || fault.errno != 0).then_some(fault.errno),
            reason,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fail-closed-linux refused to start {}: layer {}, step {}: {}; the provider was not started",
            self.provider, self.layer, self.step, self.reason
        )
    }
}

impl std::error::Error for Refusal {}

/// One provider to start: its name, its executable, its arguments and the one
/// directory it may read and write.
#[derive(Clone, Debug)]
pub struct ProviderSpec {
    name: String,
    executable: PathBuf,
    args: Vec<OsString>,
    storage_root: PathBuf,
    landlock_abi_floor: u32,
    extra_needed_mask: i32,
    extra_read_paths: Vec<PathBuf>,
    test_empty_pipe: bool,
    test_confine_ready: bool,
    test_lie_rights: bool,
    test_close_pipe: bool,
    test_lie_enforcement: bool,
}

impl ProviderSpec {
    pub fn new(
        name: impl Into<String>,
        executable: impl Into<PathBuf>,
        storage_root: impl Into<PathBuf>,
    ) -> ProviderSpec {
        ProviderSpec {
            name: name.into(),
            executable: executable.into(),
            args: Vec::new(),
            storage_root: storage_root.into(),
            landlock_abi_floor: 0,
            extra_needed_mask: 0,
            extra_read_paths: Vec::new(),
            test_empty_pipe: false,
            test_confine_ready: false,
            test_lie_rights: false,
            test_close_pipe: false,
            test_lie_enforcement: false,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> ProviderSpec {
        self.args.push(arg.into());
        self
    }

    /// Raises the Landlock ABI this provider needs on top of the per-right
    /// check. It cannot skip a needed right the kernel lacks.
    pub fn require_landlock_abi(mut self, abi: u32) -> ProviderSpec {
        self.landlock_abi_floor = abi;
        self
    }

    /// Test-only: require an extra right on top of the file profile.
    /// The extra right can only add a refusal. It cannot drop truncate or
    /// `ioctl_dev`. Used with the `FCL_TEST_HOOKS` CLI switch.
    pub fn require_test_right(mut self, mask: i32) -> ProviderSpec {
        self.extra_needed_mask |= mask;
        self
    }

    /// Extra path the provider may open for read only. Used to plant a
    /// character device the probe opens after `restrict_self`.
    pub fn readable_path(mut self, path: impl Into<PathBuf>) -> ProviderSpec {
        self.extra_read_paths.push(path.into());
        self
    }

    /// Test-only: the child exits before it writes a fault or starts.
    pub fn test_empty_pipe(mut self) -> ProviderSpec {
        self.test_empty_pipe = true;
        self
    }

    /// Test-only: the child writes `ConfineReady` and exits without `execve`.
    pub fn test_confine_ready(mut self) -> ProviderSpec {
        self.test_confine_ready = true;
        self
    }

    /// Test-only: the rights probe reports every needed right missing.
    pub fn test_lie_rights(mut self) -> ProviderSpec {
        self.test_lie_rights = true;
        self
    }

    /// Test-only: close the fault pipe and exit without `execve`.
    pub fn test_close_pipe(mut self) -> ProviderSpec {
        self.test_close_pipe = true;
        self
    }

    /// Test-only: the enforcement self-test reports a denied op succeeded.
    pub fn test_lie_enforcement(mut self) -> ProviderSpec {
        self.test_lie_enforcement = true;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Everything the guard needs, built before fork so the guard never
/// allocates in the child.
pub struct Plan {
    provider: String,
    executable: CString,
    _argv: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    envp_ptrs: Vec<*const c_char>,
    storage_root: CString,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    filter: Vec<libc::sock_filter>,
    abi_floor: u32,
    extra_needed_mask: i32,
    extra_read: Vec<CString>,
    exe_dev: u64,
    exe_ino: u64,
    enforce_file: CString,
    enforce_tty: CString,
    enforce_dir: Option<PathBuf>,
    enforce_master: RawFd,
    test_empty_pipe: bool,
    test_confine_ready: bool,
    test_lie_rights: bool,
    test_close_pipe: bool,
    test_lie_enforcement: bool,
}

impl Plan {
    pub fn new(spec: &ProviderSpec) -> Result<Plan, Refusal> {
        let abi_floor = spec.landlock_abi_floor;
        let invalid = || {
            Refusal::new(
                &spec.name,
                Fault::os(Step::Prepare, libc::EINVAL),
                abi_floor,
            )
        };
        if !spec.executable.is_absolute() || !spec.storage_root.is_absolute() {
            return Err(invalid());
        }
        let executable = c_string(spec.executable.as_os_str()).ok_or_else(invalid)?;
        let storage_root = c_string(spec.storage_root.as_os_str()).ok_or_else(invalid)?;
        let mut extra_read = Vec::new();
        for path in &spec.extra_read_paths {
            if !path.is_absolute() {
                return Err(invalid());
            }
            extra_read.push(c_string(path.as_os_str()).ok_or_else(invalid)?);
        }
        let (exe_dev, exe_ino) = stat_dev_ino(&executable).ok_or_else(invalid)?;
        let (enforce_file, enforce_dir) = create_enforce_file().ok_or_else(invalid)?;
        let (enforce_master, enforce_tty) = match open_pty_cstr() {
            Some(pair) => pair,
            None => {
                let _ = std::fs::remove_dir_all(&enforce_dir);
                return Err(invalid());
            }
        };
        extra_read.push(enforce_tty.clone());
        let mut argv = vec![executable.clone()];
        for arg in &spec.args {
            argv.push(c_string(arg).ok_or_else(invalid)?);
        }
        let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        // SAFETY: getuid and getgid cannot fail and touch no memory.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Ok(Plan {
            provider: spec.name.clone(),
            executable,
            _argv: argv,
            argv_ptrs,
            envp_ptrs: vec![std::ptr::null()],
            storage_root,
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
            filter: seccomp::filter(),
            abi_floor,
            extra_needed_mask: spec.extra_needed_mask,
            extra_read,
            exe_dev,
            exe_ino,
            enforce_file,
            enforce_tty,
            enforce_dir: Some(enforce_dir),
            enforce_master,
            test_empty_pipe: spec.test_empty_pipe,
            test_confine_ready: spec.test_confine_ready,
            test_lie_rights: spec.test_lie_rights,
            test_close_pipe: spec.test_close_pipe,
            test_lie_enforcement: spec.test_lie_enforcement,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn executable(&self) -> &CStr {
        &self.executable
    }

    /// NULL-terminated argument vector for `execve`.
    pub fn argv(&self) -> *const *const c_char {
        self.argv_ptrs.as_ptr()
    }

    /// NULL-terminated, empty environment for `execve`.
    pub fn envp(&self) -> *const *const c_char {
        self.envp_ptrs.as_ptr()
    }

    /// Device and inode of the expected executable, from `stat` before fork.
    pub fn exe_dev_ino(&self) -> (u64, u64) {
        (self.exe_dev, self.exe_ino)
    }

    pub fn enforce_file(&self) -> &CStr {
        &self.enforce_file
    }

    pub fn enforce_tty(&self) -> &CStr {
        &self.enforce_tty
    }

    pub fn storage_root(&self) -> &CStr {
        &self.storage_root
    }
}

impl Drop for Plan {
    fn drop(&mut self) {
        if self.enforce_master >= 0 {
            // SAFETY: we own this pty master for the life of the plan.
            unsafe { libc::close(self.enforce_master) };
            self.enforce_master = -1;
        }
        if let Some(dir) = self.enforce_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn c_string(value: &OsStr) -> Option<CString> {
    CString::new(value.as_bytes()).ok()
}

/// `stat` device and inode for an absolute path. None if the path is missing.
pub fn stat_dev_ino(path: &CStr) -> Option<(u64, u64)> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: `path` is NUL-terminated; `st` is a valid out pointer.
    if unsafe { libc::stat(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev, st.st_ino))
}

/// True only when both sides name the same existing file.
pub fn exe_identity_ok(expected: (u64, u64), found: Option<(u64, u64)>) -> bool {
    match found {
        Some(got) => got == expected && expected.0 != 0 && expected.1 != 0,
        None => false,
    }
}

/// Device and inode of `/proc/<pid>/exe`. Allocates; parent side only.
pub fn proc_exe_dev_ino(pid: u32) -> Option<(u64, u64)> {
    let path = format!("/proc/{pid}/exe");
    let c_path = CString::new(path).ok()?;
    stat_dev_ino(&c_path)
}

fn create_enforce_file() -> Option<(CString, PathBuf)> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fcl-enf-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join("probe");
    std::fs::write(&path, b"x").ok()?;
    let c_path = c_string(path.as_os_str())?;
    Some((c_path, dir))
}

fn open_pty_cstr() -> Option<(RawFd, CString)> {
    // SAFETY: posix_openpt / grantpt / unlockpt / ptsname_r are the usual pty setup.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return None;
        }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            libc::close(master);
            return None;
        }
        let mut buf = [0u8; 64];
        if libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len()) != 0 {
            libc::close(master);
            return None;
        }
        let path = CStr::from_ptr(buf.as_ptr().cast()).to_owned();
        Some((master, path))
    }
}

/// The process operations the guard needs, one method per step. Each method
/// returns the OS error number on failure. The real kernel runs them between
/// fork and exec, so an implementation must not allocate or panic.
pub trait Kernel {
    fn unshare_user_namespace(&mut self) -> Result<(), Errno>;
    fn unshare_pid_namespace(&mut self) -> Result<(), Errno>;
    /// After `unshare(CLONE_NEWPID)`, fork the PID-namespace init and leave
    /// immediately. A simulated kernel does nothing.
    fn detach_into_pid_namespace(&mut self) -> Result<(), Errno> {
        let _ = self;
        Ok(())
    }
    fn write_uid_map(&mut self, map: &[u8]) -> Result<(), Errno>;
    fn deny_setgroups(&mut self) -> Result<(), Errno>;
    fn write_gid_map(&mut self, map: &[u8]) -> Result<(), Errno>;
    fn last_capability(&mut self) -> Result<u32, Errno>;
    fn drop_bounding_capability(&mut self, cap: u32) -> Result<(), Errno>;
    fn clear_ambient_capabilities(&mut self) -> Result<(), Errno>;
    fn clear_capability_sets(&mut self) -> Result<(), Errno>;
    fn set_no_new_privs(&mut self) -> Result<(), Errno>;
    /// After the maps and capability drop: `PR_SET_DUMPABLE` 0, and make
    /// the granted binary execute-only so `execve` does not raise dumpable.
    fn set_not_dumpable(&mut self, executable: &CStr) -> Result<(), Errno> {
        let _ = (self, executable);
        Ok(())
    }
    fn install_seccomp_filter(&mut self, filter: &[libc::sock_filter]) -> Result<(), Errno>;
    /// Replace a terminal or a socket on fd 0, 1 or 2. On failure
    /// `named_fault_found` is that fd.
    fn sanitize_stdio(&mut self) -> Result<(), Errno> {
        let _ = self;
        Ok(())
    }
    /// Second seccomp filter: `execveat` always EPERM; `execve` EPERM except
    /// the helper's granted-path pointer. A failed install refuses the launch.
    fn install_no_exec_filter(&mut self, plan: &Plan) -> Result<(), Errno> {
        let _ = (self, plan);
        Ok(())
    }
    /// Fd named by the last `sanitize_stdio` failure. 0 when none.
    fn named_fault_found(&self) -> u32 {
        let _ = self;
        0
    }
    fn landlock_abi(&mut self) -> Result<u32, Errno>;
    fn landlock_create_ruleset(
        &mut self,
        handled_fs: u64,
        handled_net: u64,
        scoped: u64,
    ) -> Result<RawFd, Errno>;
    fn landlock_add_path_rule(
        &mut self,
        ruleset: RawFd,
        path: &CStr,
        access: u64,
    ) -> Result<(), Errno>;
    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno>;
    /// Close every fd except stdin, stdout, stderr and the kernel's keep list.
    fn close_unneeded_fds(&mut self) -> Result<(), Errno> {
        let _ = self;
        Ok(())
    }
    /// After `restrict_self`, try one denied op per needed right. Ok means
    /// every denied op failed. Err means a denied op succeeded or the test
    /// could not run.
    fn enforcement_self_test(&mut self, plan: &Plan) -> Result<(), Errno> {
        let _ = (self, plan);
        Ok(())
    }
    /// Try-create a ruleset that handles only `access`. Ok(false) means
    /// the kernel returned EINVAL: it does not have that right.
    fn landlock_can_handle_fs(&mut self, access: u64) -> Result<bool, Errno> {
        match self.landlock_create_ruleset(access, 0, 0) {
            Ok(_) => Ok(true),
            Err(errno) if errno == libc::EINVAL => Ok(false),
            Err(errno) => Err(errno),
        }
    }
    /// Replaces the process image with the provider. On a real kernel this
    /// returns only on failure.
    fn exec(&mut self, plan: &Plan) -> Result<(), Errno>;
    /// Starts a new process that runs `confine_and_exec`, and returns either
    /// the provider's pid or the guard's fault.
    fn spawn_confined(&mut self, plan: &Plan) -> Result<u32, Fault>;
}

/// Applies the six layers to the calling process, in order, and stops at the
/// first failed step.
pub fn confine<K: Kernel + ?Sized>(kernel: &mut K, plan: &Plan) -> Result<(), Fault> {
    let os = |step: Step| move |errno: Errno| Fault::os(step, errno);

    kernel.unshare_user_namespace().map_err(os(Step::Unshare))?;
    kernel
        .write_uid_map(&plan.uid_map)
        .map_err(os(Step::UidMap))?;
    kernel.deny_setgroups().map_err(os(Step::Setgroups))?;
    kernel
        .write_gid_map(&plan.gid_map)
        .map_err(os(Step::GidMap))?;
    kernel
        .unshare_pid_namespace()
        .map_err(os(Step::UnsharePid))?;

    // The bounding set first: dropping it needs CAP_SETPCAP, which capset removes.
    let last = kernel.last_capability().map_err(os(Step::LastCapability))?;
    for cap in 0..=last {
        kernel
            .drop_bounding_capability(cap)
            .map_err(os(Step::BoundingSet))?;
    }
    kernel
        .clear_ambient_capabilities()
        .map_err(os(Step::AmbientSet))?;
    kernel
        .clear_capability_sets()
        .map_err(os(Step::CapabilitySets))?;

    kernel.set_no_new_privs().map_err(os(Step::SetNoNewPrivs))?;
    kernel
        .set_not_dumpable(plan.executable())
        .map_err(os(Step::SetDumpable))?;

    kernel
        .install_seccomp_filter(&plan.filter)
        .map_err(os(Step::InstallFilter))?;

    let abi = kernel.landlock_abi().map_err(os(Step::AbiProbe))?;
    // Name a missing right first. The extra ABI floor must not hide it.
    if let Some(mask) = missing_required_mask_with(abi, plan.extra_needed_mask) {
        return Err(Fault::missing_rights(abi, mask));
    }
    if abi < plan.abi_floor {
        return Err(Fault::abi_floor(abi));
    }
    let mut probed = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        match kernel.landlock_can_handle_fs(right.access) {
            Ok(true) => {}
            Ok(false) => probed |= right.mask,
            Err(errno) => return Err(Fault::os(Step::RightProbe, errno)),
        }
    }
    if probed != 0 {
        return Err(Fault::right_probe(abi, probed));
    }
    let ruleset = kernel
        .landlock_create_ruleset(
            handled_fs_for_abi(abi),
            handled_net_for_abi(abi),
            scoped_for_abi(abi),
        )
        .map_err(os(Step::CreateRuleset))?;
    kernel
        .landlock_add_path_rule(ruleset, &plan.storage_root, landlock::STORAGE_ROOT_ACCESS)
        .map_err(os(Step::StorageRootRule))?;
    kernel
        .landlock_add_path_rule(ruleset, &plan.executable, landlock::EXECUTABLE_ACCESS)
        .map_err(os(Step::ExecutableRule))?;
    for path in &plan.extra_read {
        kernel
            .landlock_add_path_rule(ruleset, path, landlock::ACCESS_FS_READ_FILE)
            .map_err(os(Step::ExecutableRule))?;
    }
    kernel.sanitize_stdio().map_err(|errno| Fault {
        step: Step::SanitizeStdio,
        errno,
        found: kernel.named_fault_found(),
    })?;
    kernel
        .landlock_restrict_self(ruleset)
        .map_err(os(Step::RestrictSelf))?;
    kernel.close_unneeded_fds().map_err(os(Step::CloseFds))?;
    Ok(())
}

/// Runs in the provider's own process. Returns only when the provider did
/// not start.
pub fn confine_and_exec<K: Kernel + ?Sized>(kernel: &mut K, plan: &Plan) -> Result<(), Fault> {
    confine(kernel, plan)?;
    kernel
        .detach_into_pid_namespace()
        .map_err(|errno| Fault::os(Step::PidFork, errno))?;
    kernel
        .install_no_exec_filter(plan)
        .map_err(|errno| Fault::os(Step::InstallNoExec, errno))?;
    kernel
        .enforcement_self_test(plan)
        .map_err(|errno| Fault::os(Step::EnforceSelf, errno))?;
    kernel
        .exec(plan)
        .map_err(|errno| Fault::os(Step::Execve, errno))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    pub provider: String,
    pub pid: u32,
}

/// How the parent reads the close-on-exec fault pipe after fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPipe {
    /// EOF on the close-on-exec write end. Launch still needs the running
    /// image to be the expected binary (`exe_identity_ok`).
    Started,
    /// Any bytes are a fault, including a `ConfineReady` record without exec.
    Refused(Fault),
}

/// Interprets everything read from the fault pipe.
///
/// EOF (`bytes` empty, no read error) means the write ends closed. That is
/// necessary for a start, not sufficient: `spawn_confined` then checks
/// `/proc/<provider pid>/exe`. Any bytes are a fault. A `ConfineReady`
/// record without `execve` is a refusal.
pub fn interpret_fault_pipe(bytes: &[u8], read_error: Option<Errno>) -> FaultPipe {
    if let Some(err) = read_error {
        return FaultPipe::Refused(Fault::os(Step::Report, err));
    }
    if bytes.is_empty() {
        return FaultPipe::Started;
    }
    if bytes.len() < Fault::ENCODED_LEN {
        return FaultPipe::Refused(Fault::os(Step::Report, libc::EPROTO));
    }
    let first = match Fault::decode(&bytes[..Fault::ENCODED_LEN]) {
        Some(fault) => fault,
        None => return FaultPipe::Refused(Fault::os(Step::Report, libc::EPROTO)),
    };
    if first.step == Step::ConfineReady {
        return FaultPipe::Refused(Fault::confine_ready());
    }
    FaultPipe::Refused(first)
}

/// Starts the provider confined, or refuses. A refusal starts nothing.
pub fn launch<K: Kernel + ?Sized>(kernel: &mut K, spec: &ProviderSpec) -> Result<Started, Refusal> {
    let plan = Plan::new(spec)?;
    match kernel.spawn_confined(&plan) {
        Ok(pid) => Ok(Started {
            provider: spec.name.clone(),
            pid,
        }),
        Err(fault) => Err(Refusal::new(&spec.name, fault, plan.abi_floor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_round_trips_through_the_pipe_encoding() {
        for step in Step::GUARD.iter().chain(Step::LAUNCH.iter()) {
            let fault = Fault {
                step: *step,
                errno: libc::EPERM,
                found: 4,
            };
            assert_eq!(Fault::decode(&fault.encode()), Some(fault), "{step}");
        }
    }

    #[test]
    fn fault_decode_rejects_a_short_record_and_an_unknown_step() {
        let bytes = Fault::os(Step::Unshare, libc::EPERM).encode();
        assert_eq!(Fault::decode(&bytes[..11]), None);
        let mut unknown = bytes;
        unknown[0..4].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(Fault::decode(&unknown), None);
    }

    #[test]
    fn file_profile_needs_truncate_and_ioctl_dev_not_refer() {
        let names: Vec<&str> = FILE_PROFILE_NEEDED_RIGHTS
            .iter()
            .map(|right| right.name)
            .collect();
        assert_eq!(names, ["truncate", "ioctl_dev"]);
        assert_eq!(
            FILE_PROFILE_NEEDED_RIGHTS[0].access,
            landlock::ACCESS_FS_TRUNCATE
        );
        assert_eq!(
            FILE_PROFILE_NEEDED_RIGHTS[1].access,
            landlock::ACCESS_FS_IOCTL_DEV
        );
        assert_eq!(
            landlock::STORAGE_ROOT_ACCESS.count_ones(),
            8,
            "keep the eight-right storage mask"
        );
        assert_eq!(
            landlock::STORAGE_ROOT_ACCESS
                & (landlock::ACCESS_FS_REFER
                    | landlock::ACCESS_FS_IOCTL_DEV
                    | landlock::ACCESS_FS_MAKE_CHAR
                    | landlock::ACCESS_FS_MAKE_SOCK
                    | landlock::ACCESS_FS_MAKE_FIFO
                    | landlock::ACCESS_FS_MAKE_BLOCK
                    | landlock::ACCESS_FS_MAKE_SYM),
            0
        );
    }

    #[test]
    fn per_right_floor_for_abi_1_through_6() {
        let expected = [
            (1, Some(MISSING_TRUNCATE | MISSING_IOCTL_DEV), false),
            (2, Some(MISSING_TRUNCATE | MISSING_IOCTL_DEV), false),
            (3, Some(MISSING_IOCTL_DEV), false),
            (4, Some(MISSING_IOCTL_DEV), false),
            (5, None, true),
            (6, None, true),
            (7, None, true),
        ];
        for (abi, mask, launches) in expected {
            assert_eq!(missing_required_mask(abi), mask, "abi {abi}");
            assert_eq!(file_profile_launches_on_abi(abi), launches, "abi {abi}");
        }
        let abi1 = missing_rights_reason(1, MISSING_TRUNCATE | MISSING_IOCTL_DEV);
        assert!(
            abi1.contains("ABI 1 cannot deny truncate (needs ABI 3)"),
            "{abi1}"
        );
        assert!(abi1.contains("ioctl_dev (needs ABI 5)"), "{abi1}");
        let abi3 = missing_rights_reason(3, MISSING_IOCTL_DEV);
        assert!(
            abi3.contains("ABI 3 cannot deny ioctl_dev (needs ABI 5)"),
            "{abi3}"
        );
        assert!(!abi3.contains("truncate"), "{abi3}");
    }

    #[test]
    fn handled_bits_follow_the_abi_and_never_invent_a_right() {
        assert_eq!(handled_fs_for_abi(1) & landlock::ACCESS_FS_TRUNCATE, 0);
        assert_eq!(handled_fs_for_abi(1) & landlock::ACCESS_FS_REFER, 0);
        assert_eq!(handled_fs_for_abi(1) & landlock::ACCESS_FS_IOCTL_DEV, 0);
        assert_ne!(handled_fs_for_abi(2) & landlock::ACCESS_FS_REFER, 0);
        assert_ne!(handled_fs_for_abi(3) & landlock::ACCESS_FS_TRUNCATE, 0);
        assert_eq!(handled_fs_for_abi(3) & landlock::ACCESS_FS_IOCTL_DEV, 0);
        assert_eq!(handled_fs_for_abi(5), landlock::HANDLED_FS);
        assert_eq!(handled_net_for_abi(3), 0);
        assert_eq!(handled_net_for_abi(4), landlock::HANDLED_NET);
        assert_eq!(scoped_for_abi(5), 0);
        assert_eq!(scoped_for_abi(6), landlock::SCOPE_SIGNAL);
        assert_eq!(ruleset_attr_size(0, 0), 8);
        assert_eq!(ruleset_attr_size(landlock::HANDLED_NET, 0), 16);
        assert_eq!(
            ruleset_attr_size(landlock::HANDLED_NET, landlock::SCOPE_SIGNAL),
            24
        );
    }

    #[test]
    fn pid_namespace_is_a_required_guard_step() {
        let guard = Step::GUARD.to_vec();
        let gid = guard.iter().position(|step| *step == Step::GidMap).unwrap();
        let pid = guard
            .iter()
            .position(|step| *step == Step::UnsharePid)
            .unwrap();
        let cap = guard
            .iter()
            .position(|step| *step == Step::LastCapability)
            .unwrap();
        assert_eq!(pid, gid + 1, "PID unshare follows the id maps");
        assert_eq!(cap, pid + 1, "capabilities follow the PID unshare");
        assert_eq!(Step::UnsharePid.layer(), Layer::PidNamespace);
        assert_eq!(Step::UnsharePid.name(), "unshare_pid");
        // ABI 5 can launch and still cannot set LANDLOCK_SCOPE_SIGNAL.
        assert_eq!(scoped_for_abi(5), 0);
        assert_eq!(scoped_for_abi(6), landlock::SCOPE_SIGNAL);
        assert_eq!(scoped_for_abi(SCOPE_SIGNAL_ABI - 1), 0);
    }

    #[test]
    fn extra_test_right_is_absent_from_the_file_profile() {
        assert_eq!(missing_required_mask(6), None);
        assert_eq!(missing_required_mask(7), None);
        assert_eq!(
            missing_required_mask_with(6, MISSING_TEST_FUTURE_FS),
            Some(MISSING_TEST_FUTURE_FS)
        );
        assert_eq!(missing_required_mask_with(7, MISSING_TEST_FUTURE_FS), None);
        assert_eq!(
            missing_required_mask_with(4, MISSING_TEST_FUTURE_FS),
            Some(MISSING_IOCTL_DEV | MISSING_TEST_FUTURE_FS)
        );
        let reason = missing_rights_reason(6, MISSING_TEST_FUTURE_FS);
        assert!(reason.contains("future_fs (needs ABI 7)"), "{reason}");
        assert!(!FILE_PROFILE_NEEDED_RIGHTS
            .iter()
            .any(|right| right.mask == MISSING_TEST_FUTURE_FS));
    }

    #[test]
    fn execve_eof_is_a_start_and_confine_ready_is_a_refusal() {
        assert_eq!(interpret_fault_pipe(&[], None), FaultPipe::Started);
        let ready = Fault::confine_ready().encode();
        assert_eq!(
            interpret_fault_pipe(&ready, None),
            FaultPipe::Refused(Fault::confine_ready())
        );
        let unshare = Fault::os(Step::Unshare, libc::EPERM).encode();
        assert_eq!(
            interpret_fault_pipe(&unshare, None),
            FaultPipe::Refused(Fault::os(Step::Unshare, libc::EPERM))
        );
        assert_eq!(
            interpret_fault_pipe(&ready[..6], None),
            FaultPipe::Refused(Fault::os(Step::Report, libc::EPROTO))
        );
        let refusal = Refusal::new("did-provider", Fault::confine_ready(), 0);
        assert!(
            refusal
                .to_string()
                .contains("ConfineReady without execve is not a start"),
            "{refusal}"
        );
        let empty = Refusal::new("did-provider", Fault::empty_pipe(), 0);
        assert!(
            empty
                .to_string()
                .contains("the child ended before it wrote a fault or started"),
            "{empty}"
        );
    }

    #[test]
    fn exe_identity_requires_matching_dev_and_inode() {
        assert!(exe_identity_ok((1, 2), Some((1, 2))));
        assert!(!exe_identity_ok((1, 2), Some((1, 3))));
        assert!(!exe_identity_ok((1, 2), Some((9, 2))));
        assert!(!exe_identity_ok((1, 2), None));
        assert!(!exe_identity_ok((0, 0), Some((0, 0))));
        let refusal = Refusal::new("did-provider", Fault::exec_identity(), 0);
        assert!(
            refusal
                .to_string()
                .contains("the running image is not the expected executable"),
            "{refusal}"
        );
        let enforce = Refusal::new("did-provider", Fault::enforce_broken(), 0);
        assert!(
            enforce
                .to_string()
                .contains("Landlock accepted a right and did not enforce it"),
            "{enforce}"
        );
        let stdio = Refusal::new(
            "did-provider",
            Fault {
                step: Step::SanitizeStdio,
                errno: libc::EPERM,
                found: 0,
            },
            0,
        );
        assert!(
            stdio
                .to_string()
                .contains("fd 0 is a terminal or a socket and could not be replaced"),
            "{stdio}"
        );
        let no_exec = Refusal::new(
            "did-provider",
            Fault::os(Step::InstallNoExec, libc::ENOSYS),
            0,
        );
        assert!(
            no_exec
                .to_string()
                .contains("the no-exec seccomp filter could not be installed"),
            "{no_exec}"
        );
    }
}
