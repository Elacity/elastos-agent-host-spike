//! Landlock file decisions for one provider launch; attachment comes later.
#![allow(dead_code)] // The spawn caller is added in a later slice.

use super::rights_table::{for_provider, RuntimeProviderId};
use std::{io, path::PathBuf};

// The lab's STORAGE_ROOT, executable, and ABI-5 handled masks (confine.rs:8560-8582, 8685).
const STORAGE: u64 = 0x41be;
const BINARY: u64 = 0x5;
const HANDLED: u64 = 0xffff;
const NO_LANDLOCK: &str = "linux confinement refused: the kernel has no Landlock";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PathRule(pub &'static str, pub PathBuf, pub u64);
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub abi: u32,
    pub handled: u64,
    pub rules: Vec<PathRule>,
}
pub(super) struct Bindings {
    pub storage_parent: PathBuf,
    pub storage_root: PathBuf,
    pub provider_executable: PathBuf,
}

pub(super) fn require_abi(reported: io::Result<u32>) -> Result<u32, String> {
    let abi = reported.map_err(|_| NO_LANDLOCK.to_string())?;
    if abi < 5 {
        return Err(format!("linux confinement refused: the Landlock ABI cannot express the default-denial file rights, which needs ABI 5 and this kernel reports ABI {abi}"));
    }
    Ok(abi)
}

#[cfg(target_os = "linux")]
fn query_abi() -> io::Result<u32> {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, 1u32) };
    if abi < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(abi as u32)
    }
}
#[cfg(not(target_os = "linux"))]
fn query_abi() -> io::Result<u32> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
pub(super) fn kernel_abi() -> Result<u32, String> {
    require_abi(query_abi())
}

pub(super) fn build(
    provider: RuntimeProviderId,
    bindings: &Bindings,
    loader: &[PathBuf],
    abi: u32,
) -> Result<Plan, String> {
    let abi = require_abi(Ok(abi))?;
    let mut rules = Vec::new();
    for row in for_provider(provider) {
        for form in row.rules {
            match *form {
                r#"(allow file-read* (literal (param "STORAGE_PARENT")))"# => {}
                r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"# => rules.push(
                    PathRule("STORAGE_ROOT", bindings.storage_root.clone(), STORAGE),
                ),
                r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"# => rules.insert(
                    0,
                    PathRule(
                        "PROVIDER_EXECUTABLE",
                        bindings.provider_executable.clone(),
                        BINARY,
                    ),
                ),
                _ => return Err(format!("Landlock has no path decision for {form}")),
            }
        }
    }
    for path in loader {
        rules.push(PathRule("LANDLOCK_LOADER_PATHS", path.clone(), BINARY));
    }
    Ok(Plan {
        abi,
        handled: HANDLED,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use RuntimeProviderId::*;
    #[test]
    fn abi_decision_matches_lab_refusals() {
        assert_eq!(require_abi(Ok(4)), Err("linux confinement refused: the Landlock ABI cannot express the default-denial file rights, which needs ABI 5 and this kernel reports ABI 4".to_string()));
        assert_eq!(
            require_abi(Err(io::Error::other("query failed"))),
            Err(NO_LANDLOCK.to_string())
        );
        for abi in [5, 6, 8] {
            assert_eq!(require_abi(Ok(abi)), Ok(abi));
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(query_abi().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn provider_plans_match_lab_file_rows() {
        // Independent oracle: wallet-provider/tests/confine.rs:8560-8582, 8667, 8880-8930.
        for provider in [Did, Wallet, Model] {
            let bindings = Bindings {
                storage_parent: "/provider".into(),
                storage_root: format!("/provider/{provider:?}").into(),
                provider_executable: format!("/bin/{provider:?}").into(),
            };
            let plan = build(provider, &bindings, &["/loader".into()], 5).unwrap();
            assert_eq!((plan.abi, plan.handled), (5, 0xffff));
            assert_eq!(
                plan.rules,
                vec![
                    PathRule("PROVIDER_EXECUTABLE", bindings.provider_executable, 0x5),
                    PathRule("STORAGE_ROOT", bindings.storage_root, 0x41be),
                    PathRule("LANDLOCK_LOADER_PATHS", "/loader".into(), 0x5),
                ]
            );
        }
    }
}
