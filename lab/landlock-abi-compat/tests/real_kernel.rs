//! The same decisions, checked against this machine's Landlock ABI.
//!
//! The probe is `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
//! A ruleset that omits TRUNCATE is created and closed here, so the test shows
//! the kernel accepts the weaker mask. Nothing calls `landlock_restrict_self`.

use landlock_abi_compat::{
    bits, decide_best_effort, decide_guard_299, decide_guard_307, decide_per_row,
    is_silently_weaker, Decision,
};
use std::io::Error;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

#[repr(C)]
struct AttrFs {
    handled_access_fs: u64,
}

#[repr(C)]
struct AttrFsNet {
    handled_access_fs: u64,
    handled_access_net: u64,
}

fn errno() -> i32 {
    Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn create_ruleset(attr: *const libc::c_void, size: usize) -> Result<i32, i32> {
    unsafe { *libc::__errno_location() = 0 };
    let rc = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr, size, 0u32) };
    if rc < 0 {
        Err(errno())
    } else {
        Ok(libc::c_int::try_from(rc).unwrap_or(libc::EBADF))
    }
}

fn close(fd: i32) {
    unsafe { libc::close(fd) };
}

fn probe_abi() -> Result<u32, i32> {
    unsafe { *libc::__errno_location() = 0 };
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<AttrFs>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        Err(errno())
    } else {
        u32::try_from(rc).map_err(|_| libc::ERANGE)
    }
}

#[test]
fn this_kernel_matches_the_pure_decisions() {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unread".to_string());
    let osrelease = osrelease.trim();
    match probe_abi() {
        Ok(abi) => {
            eprintln!("real kernel osrelease={osrelease} landlock_abi={abi}");
            assert!(abi >= 1, "ABI {abi} on {osrelease}");
            let host = Some(abi);
            assert!(!is_silently_weaker(&decide_guard_299(host), host));
            assert!(!is_silently_weaker(&decide_guard_307(host), host));
            assert!(!is_silently_weaker(&decide_per_row(host), host));
            if abi >= 5 {
                assert_eq!(decide_guard_299(host), Decision::RunConfined);
                assert_eq!(decide_guard_307(host), Decision::RunConfined);
                assert_eq!(decide_per_row(host), Decision::RunConfined);
                assert_eq!(decide_best_effort(host), Decision::RunConfined);
            } else {
                assert!(matches!(decide_per_row(host), Decision::Refuse { .. }));
                assert!(matches!(
                    decide_best_effort(host),
                    Decision::RunWeaker { .. }
                ));
            }
            // A mask the kernel accepts is still a refusal in the per-row rule
            // when that mask is only the ABI 1 filesystem rights.
            assert!(matches!(decide_per_row(Some(1)), Decision::Refuse { .. }));
            assert!(is_silently_weaker(&decide_best_effort(Some(1)), Some(1)));
        }
        Err(err) => {
            eprintln!(
                "real kernel osrelease={osrelease} landlock_probe_errno={err} ({})",
                Error::from_raw_os_error(err)
            );
            assert!(
                err == libc::ENOSYS || err == libc::EOPNOTSUPP,
                "unexpected landlock probe errno {err}"
            );
            assert!(matches!(decide_guard_299(None), Decision::Refuse { .. }));
            assert!(matches!(decide_guard_307(None), Decision::Refuse { .. }));
            assert!(matches!(decide_per_row(None), Decision::Refuse { .. }));
            assert!(matches!(
                decide_best_effort(None),
                Decision::RunWeaker { .. }
            ));
        }
    }
}

#[test]
fn this_kernel_accepts_a_ruleset_that_omits_truncate_and_ioctl() {
    let abi = match probe_abi() {
        Ok(abi) => abi,
        Err(err) => {
            assert!(
                err == libc::ENOSYS || err == libc::EOPNOTSUPP,
                "unexpected landlock probe errno {err}"
            );
            eprintln!("landlock probe errno {err}; this kernel exposes no ruleset to create");
            return;
        }
    };
    // ABI 1 handled bits: no TRUNCATE (bit 14) and no IOCTL_DEV (bit 15).
    let weaker = AttrFs {
        handled_access_fs: bits::FS_ABI1,
    };
    let fd = create_ruleset(
        std::ptr::from_ref(&weaker).cast(),
        std::mem::size_of::<AttrFs>(),
    )
    .unwrap_or_else(|err| panic!("ABI {abi} rejected the ABI 1 mask: errno {err}"));
    close(fd);
    assert_eq!(weaker.handled_access_fs & bits::FS_TRUNCATE, 0);
    assert_eq!(weaker.handled_access_fs & bits::FS_IOCTL_DEV, 0);

    let unknown = AttrFsNet {
        handled_access_fs: bits::FS_ABI5_ALL | (1 << 16),
        handled_access_net: bits::NET_BIND_TCP | bits::NET_CONNECT_TCP,
    };
    let rejected = create_ruleset(
        std::ptr::from_ref(&unknown).cast(),
        std::mem::size_of::<AttrFsNet>(),
    );
    assert_eq!(rejected, Err(libc::EINVAL));
}
