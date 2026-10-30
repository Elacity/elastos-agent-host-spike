use std::fmt;
use std::io;

/// Every refusal starts with this text. It is the text the Linux design
/// (`capsules/wallet-provider/CONFINEMENT-LINUX.md`, "When a primitive is
/// missing") gives each refusal.
pub const REASON_PREFIX: &str = "linux confinement refused: ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderKind {
    Did,
    Wallet,
    Model,
}

impl ProviderKind {
    pub const ALL: [ProviderKind; 3] =
        [ProviderKind::Did, ProviderKind::Wallet, ProviderKind::Model];

    pub fn name(self) -> &'static str {
        match self {
            ProviderKind::Did => "did-provider",
            ProviderKind::Wallet => "wallet-provider",
            ProviderKind::Model => "model-provider",
        }
    }

    pub fn from_name(name: &str) -> Option<ProviderKind> {
        ProviderKind::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
    }
}

/// A confinement layer the guard requires, in the order the guard applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    UserNamespace,
    CapabilityDrop,
    NoNewPrivs,
    Seccomp,
    Landlock,
}

/// One way a layer can fail to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    UserNamespaceOff,
    IdMapRefused,
    CapabilityDrop,
    NoNewPrivs,
    SeccompInstall,
    LandlockMissing,
    LandlockTooOld { found: u32 },
    LandlockApply,
}

// A fault crosses `fork` as the error number of the `pre_exec` failure: the
// standard library returns that number from `spawn`. Layout, high to low byte:
// tag, fault code, ABI the kernel reported, error number.
const WIRE_TAG: i32 = 0x5C;

impl Fault {
    pub fn layer(self) -> Layer {
        match self {
            Fault::UserNamespaceOff | Fault::IdMapRefused => Layer::UserNamespace,
            Fault::CapabilityDrop => Layer::CapabilityDrop,
            Fault::NoNewPrivs => Layer::NoNewPrivs,
            Fault::SeccompInstall => Layer::Seccomp,
            Fault::LandlockMissing | Fault::LandlockTooOld { .. } | Fault::LandlockApply => {
                Layer::Landlock
            }
        }
    }

    /// The reason line, without the error-number detail.
    pub fn summary(self, needed_abi: u32) -> String {
        let text = match self {
            Fault::UserNamespaceOff => "user namespaces are turned off".to_string(),
            Fault::IdMapRefused => "the user namespace id maps cannot be written".to_string(),
            Fault::CapabilityDrop => "the capability set cannot be dropped".to_string(),
            Fault::NoNewPrivs => "no_new_privs cannot be set".to_string(),
            Fault::SeccompInstall => "the seccomp filter cannot be installed".to_string(),
            Fault::LandlockMissing => "the kernel has no Landlock".to_string(),
            Fault::LandlockTooOld { found } => format!(
                "the Landlock ABI cannot express the STORAGE_ROOT row (needs ABI {needed_abi}, this kernel reports ABI {found})"
            ),
            Fault::LandlockApply => "the Landlock ruleset cannot be applied".to_string(),
        };
        format!("{REASON_PREFIX}{text}")
    }

    fn step(self) -> Option<&'static str> {
        match self {
            Fault::UserNamespaceOff => Some("unshare(CLONE_NEWUSER)"),
            Fault::IdMapRefused => Some("write of setgroups, gid_map or uid_map"),
            Fault::CapabilityDrop => Some("capability bounding set drop or capset"),
            Fault::NoNewPrivs => Some("prctl(PR_SET_NO_NEW_PRIVS)"),
            Fault::SeccompInstall => Some("seccomp(SECCOMP_SET_MODE_FILTER)"),
            Fault::LandlockMissing => Some("landlock_create_ruleset(VERSION)"),
            Fault::LandlockTooOld { .. } => None,
            Fault::LandlockApply => Some("landlock ruleset create, add_rule or restrict_self"),
        }
    }

    fn code(self) -> i32 {
        match self {
            Fault::UserNamespaceOff => 1,
            Fault::IdMapRefused => 2,
            Fault::CapabilityDrop => 3,
            Fault::NoNewPrivs => 4,
            Fault::SeccompInstall => 5,
            Fault::LandlockMissing => 6,
            Fault::LandlockTooOld { .. } => 7,
            Fault::LandlockApply => 8,
        }
    }

    /// Pack a fault and an error number into one `i32` for `from_raw_os_error`.
    /// No allocation: it runs between `fork` and `exec`.
    pub fn to_wire(self, errno: i32) -> i32 {
        let found = match self {
            Fault::LandlockTooOld { found } => found.min(255) as i32,
            _ => 0,
        };
        (WIRE_TAG << 24) | (self.code() << 16) | (found << 8) | errno.clamp(0, 255)
    }

    /// `None` for any value that is not a packed fault, such as the error
    /// number of a failed `exec`.
    pub fn from_wire(raw: i32) -> Option<(Fault, i32)> {
        if (raw >> 24) & 0xFF != WIRE_TAG {
            return None;
        }
        let errno = raw & 0xFF;
        let found = ((raw >> 8) & 0xFF) as u32;
        let fault = match (raw >> 16) & 0xFF {
            1 => Fault::UserNamespaceOff,
            2 => Fault::IdMapRefused,
            3 => Fault::CapabilityDrop,
            4 => Fault::NoNewPrivs,
            5 => Fault::SeccompInstall,
            6 => Fault::LandlockMissing,
            7 => Fault::LandlockTooOld { found },
            8 => Fault::LandlockApply,
            _ => return None,
        };
        Some((fault, errno))
    }
}

/// The guard refused to start a provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub provider: ProviderKind,
    pub fault: Fault,
    pub errno: i32,
    pub needed_abi: u32,
}

impl Refusal {
    pub fn layer(&self) -> Layer {
        self.fault.layer()
    }

    /// The reason line with the failing step and its system error.
    pub fn reason(&self) -> String {
        let base = self.fault.summary(self.needed_abi);
        match self.fault.step() {
            Some(step) => format!(
                "{base} ({step}: {})",
                io::Error::from_raw_os_error(self.errno)
            ),
            None => base,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} not started: {}", self.provider.name(), self.reason())
    }
}

impl std::error::Error for Refusal {}
