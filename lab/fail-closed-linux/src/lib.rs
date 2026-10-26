//! Fail-closed provider launch guard for Linux (M1 C0 lab).
//!
//! The guard runs in the provider's own process, after fork and before exec.
//! It applies five layers in this order: user namespace, capability drop,
//! no_new_privs, seccomp, Landlock. Landlock uses a per-right floor: the
//! profile's needed rights are checked against the probed ABI, and a missing
//! right refuses with the right and the ABI that first expresses it. The first
//! step that fails stops the guard and becomes a refusal that names the
//! provider, the layer, the step and the OS error. The exec call is reached
//! only after every step succeeded. `launch` has no unconfined path: a
//! refusal starts nothing.

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

/// Bit in `Fault.errno` when `Step::AbiFloor` names a missing `truncate`.
pub const MISSING_TRUNCATE: i32 = 1;
/// Bit in `Fault.errno` when `Step::AbiFloor` names a missing `ioctl_dev`.
pub const MISSING_IOCTL_DEV: i32 = 2;

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
}

/// Rights whose absence leaves the sandbox wider than `(deny default)`.
pub const FILE_PROFILE_NEEDED_RIGHTS: &[NeededRight] = &[
    NeededRight {
        name: "truncate",
        minimum_abi: TRUNCATE_ABI,
        mask: MISSING_TRUNCATE,
    },
    NeededRight {
        name: "ioctl_dev",
        minimum_abi: IOCTL_DEV_ABI,
        mask: MISSING_IOCTL_DEV,
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
    let mut mask = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        if abi < right.minimum_abi {
            mask |= right.mask;
        }
    }
    (mask != 0).then_some(mask)
}

/// Reason text for a missing-right refusal. Names each right and the ABI
/// that first expresses it.
pub fn missing_rights_reason(abi: u32, mask: i32) -> String {
    let names: Vec<String> = FILE_PROFILE_NEEDED_RIGHTS
        .iter()
        .filter(|right| mask & right.mask != 0)
        .map(|right| format!("{} (needs ABI {})", right.name, right.minimum_abi))
        .collect();
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
    LastCapability,
    BoundingSet,
    AmbientSet,
    CapabilitySets,
    SetNoNewPrivs,
    InstallFilter,
    AbiProbe,
    AbiFloor,
    CreateRuleset,
    StorageRootRule,
    ExecutableRule,
    RestrictSelf,
    Execve,
    Prepare,
    Pipe,
    Fork,
    Report,
}

impl Step {
    /// The steps that run in the provider's process, in guard order.
    pub const GUARD: [Step; 17] = [
        Step::Unshare,
        Step::UidMap,
        Step::Setgroups,
        Step::GidMap,
        Step::LastCapability,
        Step::BoundingSet,
        Step::AmbientSet,
        Step::CapabilitySets,
        Step::SetNoNewPrivs,
        Step::InstallFilter,
        Step::AbiProbe,
        Step::AbiFloor,
        Step::CreateRuleset,
        Step::StorageRootRule,
        Step::ExecutableRule,
        Step::RestrictSelf,
        Step::Execve,
    ];
    const LAUNCH: [Step; 4] = [Step::Prepare, Step::Pipe, Step::Fork, Step::Report];

    pub fn layer(self) -> Layer {
        match self {
            Step::Unshare | Step::UidMap | Step::Setgroups | Step::GidMap => Layer::UserNamespace,
            Step::LastCapability | Step::BoundingSet | Step::AmbientSet | Step::CapabilitySets => {
                Layer::Capabilities
            }
            Step::SetNoNewPrivs => Layer::NoNewPrivs,
            Step::InstallFilter => Layer::Seccomp,
            Step::AbiProbe
            | Step::AbiFloor
            | Step::CreateRuleset
            | Step::StorageRootRule
            | Step::ExecutableRule
            | Step::RestrictSelf => Layer::Landlock,
            Step::Execve => Layer::Exec,
            Step::Prepare | Step::Pipe | Step::Fork | Step::Report => Layer::Launch,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Step::Unshare => "unshare",
            Step::UidMap => "uid_map",
            Step::Setgroups => "setgroups",
            Step::GidMap => "gid_map",
            Step::LastCapability => "cap_last_cap",
            Step::BoundingSet => "bounding_set",
            Step::AmbientSet => "ambient_set",
            Step::CapabilitySets => "capset",
            Step::SetNoNewPrivs => "set_no_new_privs",
            Step::InstallFilter => "install_filter",
            Step::AbiProbe => "abi_probe",
            Step::AbiFloor => "abi_floor",
            Step::CreateRuleset => "create_ruleset",
            Step::StorageRootRule => "storage_root_rule",
            Step::ExecutableRule => "executable_rule",
            Step::RestrictSelf => "restrict_self",
            Step::Execve => "execve",
            Step::Prepare => "prepare",
            Step::Pipe => "pipe",
            Step::Fork => "fork",
            Step::Report => "report",
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
            Step::AbiFloor => missing_rights_reason(fault.found, fault.errno),
            Step::AbiProbe => format!(
                "Landlock is not available: {}",
                io::Error::from_raw_os_error(fault.errno)
            ),
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
}

fn c_string(value: &OsStr) -> Option<CString> {
    CString::new(value.as_bytes()).ok()
}

/// The process operations the guard needs, one method per step. Each method
/// returns the OS error number on failure. The real kernel runs them between
/// fork and exec, so an implementation must not allocate or panic.
pub trait Kernel {
    fn unshare_user_namespace(&mut self) -> Result<(), Errno>;
    fn write_uid_map(&mut self, map: &[u8]) -> Result<(), Errno>;
    fn deny_setgroups(&mut self) -> Result<(), Errno>;
    fn write_gid_map(&mut self, map: &[u8]) -> Result<(), Errno>;
    fn last_capability(&mut self) -> Result<u32, Errno>;
    fn drop_bounding_capability(&mut self, cap: u32) -> Result<(), Errno>;
    fn clear_ambient_capabilities(&mut self) -> Result<(), Errno>;
    fn clear_capability_sets(&mut self) -> Result<(), Errno>;
    fn set_no_new_privs(&mut self) -> Result<(), Errno>;
    fn install_seccomp_filter(&mut self, filter: &[libc::sock_filter]) -> Result<(), Errno>;
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
    /// Replaces the process image with the provider. On a real kernel this
    /// returns only on failure.
    fn exec(&mut self, plan: &Plan) -> Result<(), Errno>;
    /// Starts a new process that runs `confine_and_exec`, and returns either
    /// the provider's pid or the guard's fault.
    fn spawn_confined(&mut self, plan: &Plan) -> Result<u32, Fault>;
}

/// Applies the five layers to the calling process, in order, and stops at the
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
        .install_seccomp_filter(&plan.filter)
        .map_err(os(Step::InstallFilter))?;

    let abi = kernel.landlock_abi().map_err(os(Step::AbiProbe))?;
    if abi < plan.abi_floor {
        return Err(Fault::abi_floor(abi));
    }
    if let Some(mask) = missing_required_mask(abi) {
        return Err(Fault::missing_rights(abi, mask));
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
    kernel
        .landlock_restrict_self(ruleset)
        .map_err(os(Step::RestrictSelf))?;
    Ok(())
}

/// Runs in the provider's own process. Returns only when the provider did
/// not start.
pub fn confine_and_exec<K: Kernel + ?Sized>(kernel: &mut K, plan: &Plan) -> Result<(), Fault> {
    confine(kernel, plan)?;
    kernel
        .exec(plan)
        .map_err(|errno| Fault::os(Step::Execve, errno))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    pub provider: String,
    pub pid: u32,
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
    fn pid_namespace_and_scope_signal_gaps() {
        // The guard unshares only CLONE_NEWUSER. A PID namespace that contains
        // the provider itself needs a grandchild after unshare(CLONE_NEWPID).
        // This lab does not take that second fork. ABI 5 can launch and still
        // cannot set LANDLOCK_SCOPE_SIGNAL.
        assert_eq!(scoped_for_abi(5), 0);
        assert_eq!(scoped_for_abi(6), landlock::SCOPE_SIGNAL);
        assert_eq!(scoped_for_abi(SCOPE_SIGNAL_ABI - 1), 0);
    }
}
