use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::Arc;

use crate::fault::{Fault, ProviderKind, Refusal};
use crate::host::HostKernel;
use crate::policy::{FsRules, Policy, SeccompProgram};

pub type Errno = i32;

/// The lowest Landlock ABI the guard accepts. The STORAGE_ROOT row needs every
/// filesystem right ABI 5 reports: REFER (ABI 2), TRUNCATE (ABI 3) and
/// IOCTL_DEV (ABI 5). A kernel that lacks one would leave that right
/// unrestricted, which is wider than the oracle, so the start is refused.
pub const REQUIRED_LANDLOCK_ABI: u32 = 5;

/// The kernel operations the guard applies, one per method.
///
/// Every method runs in the provider's own process between `fork` and `exec`.
/// An implementation must be async-signal-safe: no allocation and no lock.
/// A method returns the error number of the failure and applies nothing the
/// guard cannot count on.
pub trait Kernel: Send + Sync + 'static {
    fn landlock_abi(&self) -> Result<u32, Errno>;
    fn unshare_user(&self) -> Result<(), Errno>;
    fn map_ids(&self) -> Result<(), Errno>;
    fn drop_capabilities(&self) -> Result<(), Errno>;
    fn set_no_new_privs(&self) -> Result<(), Errno>;
    fn install_seccomp(&self, program: &SeccompProgram) -> Result<(), Errno>;
    fn landlock_restrict(&self, rules: &FsRules) -> Result<(), Errno>;
}

#[derive(Debug)]
pub enum LaunchError {
    /// A confinement layer could not be applied. The provider did not start.
    Refused(Refusal),
    /// The start failed for another reason, such as a missing executable.
    /// The provider did not start.
    Spawn(io::Error),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::Refused(refusal) => refusal.fmt(f),
            LaunchError::Spawn(error) => write!(f, "provider not started: {error}"),
        }
    }
}

impl std::error::Error for LaunchError {}

struct Config<K> {
    kernel: K,
    policy: Policy,
}

pub struct Guard<K: Kernel> {
    config: Arc<Config<K>>,
    needed_abi: u32,
}

impl Guard<HostKernel> {
    /// The guard over this host's kernel.
    pub fn host(policy: Policy) -> Self {
        Guard::with_kernel(HostKernel::new(), policy)
    }
}

impl<K: Kernel> Guard<K> {
    pub fn with_kernel(kernel: K, policy: Policy) -> Self {
        Guard {
            config: Arc::new(Config { kernel, policy }),
            needed_abi: REQUIRED_LANDLOCK_ABI,
        }
    }

    /// Raise the Landlock ABI the guard needs. A value below
    /// [`REQUIRED_LANDLOCK_ABI`] changes nothing: the floor cannot be lowered.
    pub fn require_landlock_abi(mut self, abi: u32) -> Self {
        self.needed_abi = self.needed_abi.max(abi);
        self
    }

    pub fn needed_landlock_abi(&self) -> u32 {
        self.needed_abi
    }

    /// Start `command` as `provider` with every layer applied, or refuse.
    ///
    /// The layers are applied in the child before `exec`. If any one fails the
    /// child stops, `exec` is never reached, and the provider image never runs.
    pub fn launch(
        &self,
        provider: ProviderKind,
        mut command: Command,
    ) -> Result<Child, LaunchError> {
        let config = Arc::clone(&self.config);
        let needed_abi = self.needed_abi;
        // SAFETY: `apply_layers` calls only `Kernel` methods, which are
        // async-signal-safe by their contract, and allocates nothing.
        unsafe {
            command.pre_exec(move || {
                apply_layers(&config.kernel, &config.policy, needed_abi)
                    .map_err(|(fault, errno)| io::Error::from_raw_os_error(fault.to_wire(errno)))
            });
        }
        match command.spawn() {
            Ok(child) => Ok(child),
            Err(error) => match error.raw_os_error().and_then(Fault::from_wire) {
                Some((fault, errno)) => Err(LaunchError::Refused(Refusal {
                    provider,
                    fault,
                    errno,
                    needed_abi,
                })),
                None => Err(LaunchError::Spawn(error)),
            },
        }
    }
}

/// Apply every layer in order and stop at the first failure.
#[rustfmt::skip]
fn apply_layers(kernel: &dyn Kernel, policy: &Policy, needed_abi: u32) -> Result<(), (Fault, Errno)> {
    kernel.unshare_user().map_err(|e| (Fault::UserNamespaceOff, e))?;
    kernel.map_ids().map_err(|e| (Fault::IdMapRefused, e))?;
    kernel.drop_capabilities().map_err(|e| (Fault::CapabilityDrop, e))?;
    kernel.set_no_new_privs().map_err(|e| (Fault::NoNewPrivs, e))?;
    kernel.install_seccomp(&policy.seccomp).map_err(|e| (Fault::SeccompInstall, e))?;
    let abi = match kernel.landlock_abi() {
        Ok(abi) => abi,
        Err(e) if e == libc::ENOSYS || e == libc::EOPNOTSUPP => return Err((Fault::LandlockMissing, e)),
        Err(e) => return Err((Fault::LandlockApply, e)),
    };
    if abi < needed_abi {
        return Err((Fault::LandlockTooOld { found: abi }, 0));
    }
    kernel.landlock_restrict(&policy.fs).map_err(|e| (Fault::LandlockApply, e))
}
