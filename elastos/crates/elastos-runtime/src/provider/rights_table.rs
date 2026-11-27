//! Runtime-owned confinement rights for the three B3 providers.

#[derive(Clone, Copy)]
pub(super) struct RightRow {
    pub id: &'static str,
    pub rules: &'static [&'static str],
    pub linux_syscalls: &'static str,
}

pub(super) static RIGHTS: &[RightRow] = &[
    RightRow {
        id: "storage",
        rules: &[
            r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#,
            r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"#,
        ],
        linux_syscalls: concat!(
            "faccessat fchmod fdatasync fstat fsync ftruncate getdents64 linkat lseek ",
            "mkdir mkdirat newfstatat openat openat2 pread64 pwrite64 read readlinkat ",
            "readv renameat2 statx unlink unlinkat"
        ),
    },
    RightRow {
        id: "bound-executable",
        rules: &[r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"#],
        linux_syscalls: "execve execveat",
    },
    RightRow {
        id: "model-gpu",
        rules: &[
            // X4 measured AGXMetalG17X on M5. The AGXMetal bundle family is
            // the narrowest rule that also starts the engine on other Apple GPUs.
            r#"(allow file-read* (regex "^/System/Library/Extensions/AGXMetal[A-Za-z0-9_]+\\.bundle(/.*)?$"))"#,
            // macOS probe X5: the pinned engine initializes Metal at gpu_layers 0.
            r#"(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient") (iokit-user-client-class "IOSurfaceRootUserClient"))"#,
            // macOS probe X6: the only measured compiler service name.
            r#"(allow mach-lookup (global-name "com.apple.MTLCompilerService"))"#,
        ],
        linux_syscalls: "",
    },
];

const DID_RIGHT_IDS: &[&str] = &["storage", "bound-executable"];
const WALLET_RIGHT_IDS: &[&str] = &["storage", "bound-executable"];
const MODEL_RIGHT_IDS: &[&str] = &["storage", "bound-executable", "model-gpu"];
/// Localhost, object, chain, and custody use the same file and exec rows.
/// A helper's extra calls live in `measured_syscalls`, not in a second storage root.
const HELPER_RIGHT_IDS: &[&str] = DID_RIGHT_IDS;

/// The caller derives this id from the Runtime's `components.json` key,
/// never from the package manifest's `name`.
///
/// macOS reads every variant: `path_allow` and `from_component_key` construct
/// them, and the Seatbelt renderer matches them. Linux reads them again when
/// it builds the filter.
#[derive(Clone, Copy, Debug)]
pub(super) enum RuntimeProviderId {
    Did,
    Wallet,
    Model,
    Localhost,
    Object,
    Chain,
    Custody,
}

impl RuntimeProviderId {
    /// Map a `components.json` key to the Runtime id. The manifest's `name` is
    /// never the input. An unknown key has no id and no grant.
    pub(super) fn from_component_key(key: &str) -> Option<Self> {
        match key {
            "did-provider" => Some(Self::Did),
            "wallet-provider" => Some(Self::Wallet),
            "model-provider" => Some(Self::Model),
            // Localhost, object, chain, and custody use the path allow-list.
            _ => None,
        }
    }

    /// Localhost, object, chain, and custody. `from_component_key` stays empty
    /// for them so `spawn_confined` cannot start them on one storage root.
    pub(super) fn path_allow(key: &str) -> Option<Self> {
        match key {
            "localhost-provider" => Some(Self::Localhost),
            "object-provider" => Some(Self::Object),
            "chain-provider" => Some(Self::Chain),
            "custody-provider" => Some(Self::Custody),
            _ => None,
        }
    }

    pub(super) fn rights(self) -> &'static [&'static str] {
        match self {
            Self::Did => DID_RIGHT_IDS,
            Self::Wallet => WALLET_RIGHT_IDS,
            Self::Model => MODEL_RIGHT_IDS,
            Self::Localhost | Self::Object | Self::Chain | Self::Custody => HELPER_RIGHT_IDS,
        }
    }

    /// Calls measured for this helper and absent from its file rows.
    /// `unlinkat` and `fchmod` stay on the storage row. `chmod` and
    /// `fchmodat` are not granted: Landlock does not mediate them, so a path
    /// chmod would reach any same-user file. Mode is `fchmod` on the held
    /// descriptor, or the mode passed at create. Chain's names are its own
    /// row: reqwest 0.12.28, tokio 1.52.1, mio 1.2.0. Chain's row names
    /// `connect`, `recvfrom`, and `sendmmsg`. Those stay on the list. They are
    /// inert unless `socket` is allowed: `seccomp_program::chain_argument_rules`
    /// allows `socket` for `AF_INET` and `AF_INET6` only, and denies `AF_UNIX`
    /// and `AF_NETLINK`. `fcntl`, `clone`, `socket`, `setsockopt`, and
    /// `getsockopt` are argument-checked, so they stay off this list. Object
    /// and localhost allow only `F_GETFL` and `F_SETFD` of `FD_CLOEXEC`:
    /// `fdopendir` needs those for `remove_dir_all`.
    ///
    /// `readlink` is x86_64 glibc `realpath`: `__readlink` is syscall
    /// `readlink` (89). Landlock does not mediate it. This filter's deny is
    /// EACCES, and `realpath` treats that errno as failure. aarch64 glibc
    /// uses `readlinkat`, which the baseline already allows; the number table
    /// has no `readlink` on that arch. Localhost calls `canonicalize` on its
    /// base path and on later paths, inside the fence. Object calls it for
    /// the auth-state cache key, also inside the fence. Chain does not, and
    /// its Linux run already passed, so `readlink` stays off the chain row.
    ///
    /// `stat` and `lstat` are the x86_64 musl 1.2.5 forms of `statx` and
    /// `newfstatat`, which these four helpers already allow. On x86_64,
    /// `kstat.st_atime_sec` is `long` (the same width as `time_t`), so
    /// `fstatat` does not try `statx` first and `fstatat_kstat` issues
    /// `SYS_stat` or `SYS_lstat`. They let metadata and realpath see a path.
    /// Landlock does not mediate stat, the same as the `statx` row. aarch64
    /// musl has no `stat` or `lstat` number, so those names drop there.
    ///
    /// `set_tid_address` lets musl `__init_tp` store this thread's
    /// clear_child_tid and read its own thread id back. A refused call leaves
    /// the id wrong and joins fail. It does not name another thread.
    /// `munmap` lets musl `free` return an mmap group to the kernel. Without
    /// it a helper that stays up keeps every large allocation. The call
    /// unmaps only an address in this process. Both numbers exist on x86_64
    /// and aarch64. Did, wallet, and model do not gain either name here.
    ///
    /// Custody adds `geteuid` (the owner check), `flock` (the store lock), and
    /// `rename`/`renameat` (the replay replace). `stat` and `lstat` are the
    /// x86_64 musl 1.2.5 metadata calls already in the number table. On
    /// aarch64, musl 1.2.3 `stat` and `lstat` tail-call `fstatat`, and that
    /// path issues `newfstatat`, so those two names drop there.
    pub(super) fn measured_syscalls(self) -> &'static str {
        match self {
            Self::Localhost => "munmap readlink rmdir set_tid_address stat lstat",
            Self::Object => "flock getpid munmap readlink rename renameat rmdir set_tid_address stat lstat",
            Self::Chain => "connect recvfrom sendmmsg epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd2 exit munmap rseq rt_sigprocmask rename renameat set_tid_address stat lstat",
            Self::Custody => "flock geteuid lstat munmap rename renameat set_tid_address stat",
            Self::Did | Self::Wallet | Self::Model => "",
        }
    }
}

pub(super) fn resolve(provider: RuntimeProviderId, dictionary: &[RightRow]) -> Vec<&RightRow> {
    provider
        .rights()
        .iter()
        .map(|id| {
            dictionary
                .iter()
                .find(|row| row.id == *id)
                .unwrap_or_else(|| panic!("Runtime right {id} is missing from the dictionary"))
        })
        .collect()
}

/// A v2 package without `rights` uses its Runtime-owned provider grant.
/// Tests are the only caller. Production admission reads `RIGHTS` directly.
#[cfg(test)]
pub(super) fn for_provider(provider: RuntimeProviderId) -> Vec<&'static RightRow> {
    resolve(provider, RIGHTS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_common::{CapsuleManifest, APPROVED_RIGHT_IDS};

    #[test]
    fn manifest_ids_and_rules_equal_runtime_table() {
        let table_ids: Vec<_> = RIGHTS.iter().map(|row| row.id).collect();
        for (name, provider) in [
            ("did-provider", RuntimeProviderId::Did),
            ("wallet-provider", RuntimeProviderId::Wallet),
            ("model-provider", RuntimeProviderId::Model),
        ] {
            let granted = for_provider(provider);
            let path = format!(
                "{}/../../../capsules/{name}/capsule.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let json = std::fs::read_to_string(&path).unwrap();
            let manifest: CapsuleManifest = serde_json::from_str(&json).unwrap();
            let rights = &manifest.authority.unwrap().rights;
            assert_eq!(
                rights
                    .iter()
                    .map(|right| right.id.as_str())
                    .collect::<Vec<_>>(),
                provider.rights(),
                "{name} ids"
            );
            for (right, row) in rights.iter().zip(&granted) {
                assert_eq!(right.rules, row.rules, "{name}: {} rules", row.id);
            }
            let mut v2: serde_json::Value = serde_json::from_str(&json).unwrap();
            v2["authority"].as_object_mut().unwrap().remove("rights");
            let v2: CapsuleManifest = serde_json::from_value(v2).unwrap();
            assert!(v2.authority.unwrap().rights.is_empty());
            assert_eq!(
                granted.iter().map(|row| row.id).collect::<Vec<_>>(),
                provider.rights(),
                "{name} omitted rights grant"
            );
        }
        assert_eq!(APPROVED_RIGHT_IDS.as_slice(), table_ids);
    }

    #[test]
    fn new_dictionary_id_is_not_granted_by_default() {
        let mut expanded = RIGHTS.to_vec();
        expanded.push(RightRow {
            id: "future-only",
            rules: &["future rule"],
            linux_syscalls: "",
        });
        for provider in [
            RuntimeProviderId::Did,
            RuntimeProviderId::Wallet,
            RuntimeProviderId::Model,
            RuntimeProviderId::Localhost,
            RuntimeProviderId::Object,
            RuntimeProviderId::Chain,
        ] {
            assert_eq!(
                resolve(provider, &expanded)
                    .iter()
                    .map(|row| row.id)
                    .collect::<Vec<_>>(),
                provider.rights(),
                "new dictionary id must require a provider grant"
            );
        }
    }

    #[test]
    fn lab_contract_ids_equal_runtime_table() {
        let lab = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../capsules/wallet-provider/tests/common/profile_generator.rs"
        ));
        let declaration = ["pub(crate) const ", "CONTRACT_RIGHTS:"].concat();
        let array_prefix = [declaration.as_str(), " [&str; "].concat();
        let declarations: Vec<_> = lab
            .lines()
            .filter(|line| line.trim_start().starts_with(declaration.as_str()))
            .collect();
        assert_eq!(
            declarations.len(),
            1,
            "expected exactly one lab CONTRACT_RIGHTS declaration"
        );
        let line = declarations[0].trim();
        let values = line
            .strip_prefix(array_prefix.as_str())
            .and_then(|line| line.split_once("] = "))
            .map(|(_, values)| values.trim_end_matches(';'))
            .expect("lab CONTRACT_RIGHTS must be one complete array declaration line");
        let ids: Vec<String> = serde_json::from_str(values)
            .expect("lab CONTRACT_RIGHTS values must be a string array");
        assert_eq!(
            ids,
            RIGHTS
                .iter()
                .map(|row| row.id.to_string())
                .collect::<Vec<_>>()
        );
    }
}
