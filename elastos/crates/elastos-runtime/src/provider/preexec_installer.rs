//! Linux provider attachment. Prepare owned buffers before fork; install in the child.

use super::super::{
    landlock_plan, rights::AdmittedRights, rights_table::RuntimeProviderId,
    seccomp_list::AuditArch, seccomp_program,
};
use std::os::fd::AsRawFd;
use std::{ffi::CString, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    CloseRange,
    NoNewPrivileges,
    Create,
    Add(usize),
    Restrict,
    Seccomp,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Failure(Step, i32);

impl Failure {
    // Three native-endian words. The child copies only stack bytes to the pipe.
    pub(super) fn record(&self) -> [u8; 12] {
        let (tag, index) = match self.0 {
            Step::CloseRange => (1u32, 0),
            Step::Create => (2, 0),
            Step::Add(index) => (3, index as u32),
            Step::NoNewPrivileges => (4, 0),
            Step::Restrict => (5, 0),
            Step::Seccomp => (6, 0),
        };
        let [t0, t1, t2, t3] = tag.to_ne_bytes();
        let [i0, i1, i2, i3] = index.to_ne_bytes();
        let [e0, e1, e2, e3] = self.1.to_ne_bytes();
        [t0, t1, t2, t3, i0, i1, i2, i3, e0, e1, e2, e3]
    }

    pub(super) fn from_record(tag: u32, index: u32, errno: i32) -> Option<Self> {
        let step = match tag {
            1 => Step::CloseRange,
            2 => Step::Create,
            3 => Step::Add(index as usize),
            4 => Step::NoNewPrivileges,
            5 => Step::Restrict,
            6 => Step::Seccomp,
            _ => return None,
        };
        Some(Self(step, errno))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(step, errno) = self;
        match step {
            Step::CloseRange => write!(f, "the probe child could not close inherited descriptors: errno {errno}"),
            Step::NoNewPrivileges => write!(f, "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno {errno}"),
            Step::Create => write!(f, "landlock install refused: the ruleset could not be created with errno {errno}"),
            Step::Add(index) => write!(f, "landlock install refused: the path rule {index} could not be added with errno {errno}"),
            Step::Restrict => write!(f, "landlock install refused: landlock_restrict_self failed with errno {errno}"),
            Step::Seccomp => write!(f, "seccomp install refused: the filter install failed with errno {errno}"),
        }
    }
}

fn sequence(count: usize, mut run: impl FnMut(Step) -> Result<(), i32>) -> Result<(), Failure> {
    let mut apply = |step| run(step).map_err(|errno| Failure(step, errno));
    apply(Step::CloseRange)?;
    apply(Step::Create)?;
    for index in 0..count {
        apply(Step::Add(index))?;
    }
    // Match the lab's Landlock installer: confine.rs:9057-9062.
    apply(Step::NoNewPrivileges)?;
    apply(Step::Restrict)?;
    apply(Step::Seccomp)
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}
#[repr(C)]
struct PathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub(super) struct Prepared {
    plan: landlock_plan::Plan,
    filters: Vec<libc::sock_filter>,
}

impl Prepared {
    pub(super) fn added_rule(&self, index: usize) -> Option<(&'static str, &std::path::Path)> {
        self.plan
            .rules
            .get(index)
            .map(|rule| (rule.0, rule.1.as_path()))
    }

    #[cfg(test)]
    pub(super) fn drop_held_for_test(&mut self, index: usize) {
        if let Some(slot) = self.plan.held.get_mut(index) {
            slot.take();
        }
    }
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("linux confinement refused: this architecture has no seccomp list");

fn host_audit_arch() -> AuditArch {
    if cfg!(target_arch = "x86_64") {
        AuditArch::X86_64
    } else {
        AuditArch::Aarch64
    }
}

fn to_sock_filters(instructions: Vec<[u32; 4]>) -> Result<Vec<libc::sock_filter>, String> {
    if instructions.is_empty() {
        return Err("seccomp install refused: the filter is empty".into());
    }
    if instructions.len() > 256 {
        return Err("seccomp install refused: the filter is too long".into());
    }
    Ok(instructions
        .into_iter()
        .map(|[code, jt, jf, k]| libc::sock_filter {
            code: code as u16,
            jt: jt as u8,
            jf: jf as u8,
            k,
        })
        .collect())
}

fn assemble(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    plan: landlock_plan::Plan,
) -> Result<Prepared, String> {
    // Refuse a NUL path before fork. The child never reads these strings.
    let _paths = plan
        .rules
        .iter()
        .map(|rule| {
            CString::new(std::os::unix::ffi::OsStrExt::as_bytes(rule.1.as_os_str()))
                .map_err(|_| format!("Landlock path contains NUL: {}", rule.0))
        })
        .collect::<Result<Vec<CString>, _>>()?;
    std::mem::drop(_paths);
    let filters = to_sock_filters(seccomp_program::program(
        provider,
        admitted,
        host_audit_arch(),
    ))?;
    Ok(Prepared { plan, filters })
}

pub(super) fn prepare(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    bindings: &landlock_plan::Bindings,
) -> Result<Prepared, String> {
    let plan = landlock_plan::build(provider, admitted, bindings, landlock_plan::kernel_abi()?)?;
    // The single-root plan has one directory root, named STORAGE_ROOT.
    // Allow-list plans pin every root in `prepare_path_allow`.
    assemble(provider, admitted, plan)
}

/// Close every descriptor from 3 up except `keep`, which is sorted and unique.
fn close_except(keep: &[i32]) -> Result<(), i32> {
    if keep.iter().any(|fd| *fd < 3) {
        return Err(libc::EINVAL);
    }
    let mut cursor = 3i32;
    for &fd in keep {
        if fd > cursor
            && unsafe { libc::syscall(libc::SYS_close_range, cursor as u32, (fd - 1) as u32, 0u32) }
                < 0
        {
            return Err(unsafe { *libc::__errno_location() });
        }
        if fd >= cursor {
            cursor = fd + 1;
        }
    }
    if unsafe { libc::syscall(libc::SYS_close_range, cursor as u32, u32::MAX, 0u32) } < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(())
}

/// # Safety
/// Call only in a forked child before exec. The caller owns fds 0–2, passes
/// its open failure-record write descriptor and the verified executable
/// descriptor (both at least 3, with FD_CLOEXEC), and writes any returned
/// failure to the report descriptor before exiting the child. Tests use -1
/// when there is no executable descriptor.
pub(super) unsafe fn install(
    prepared: &Prepared,
    keep: i32,
    executable: i32,
) -> Result<(), Failure> {
    let mut ruleset = -1;
    let result = sequence(prepared.plan.rules.len(), |step| {
        let answer = match step {
            Step::CloseRange => {
                if keep < 3 || (executable != -1 && (executable < 3 || executable == keep)) {
                    return Err(libc::EINVAL);
                }
                let mut keep_fds = vec![keep];
                if executable >= 0 {
                    keep_fds.push(executable);
                }
                for fd in prepared.plan.held.iter().flatten() {
                    let raw = fd.as_raw_fd();
                    if raw >= 3 {
                        keep_fds.push(raw);
                    }
                }
                keep_fds.sort_unstable();
                keep_fds.dedup();
                close_except(&keep_fds)?;
                0
            }
            Step::NoNewPrivileges => unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as libc::c_long
            },
            Step::Create => {
                let attr = RulesetAttr {
                    handled_access_fs: prepared.plan.handled,
                };
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_create_ruleset,
                        &attr,
                        std::mem::size_of::<RulesetAttr>(),
                        0u32,
                    )
                };
                if fd >= 0 {
                    ruleset = fd as i32;
                }
                fd
            }
            Step::Add(index) => {
                let Some(rule) = prepared.plan.rules.get(index) else {
                    return Err(libc::EINVAL);
                };
                // The descriptor was opened when the path was checked. The
                // child does not open the path again, so a swapped name is
                // not the rule. The executable rule uses the verified
                // descriptor when launch has one.
                let parent_fd = if rule.0 == "PROVIDER_EXECUTABLE" && executable >= 0 {
                    executable
                } else {
                    match prepared.plan.held.get(index).and_then(|slot| slot.as_ref()) {
                        Some(held) => held.as_raw_fd(),
                        None => return Err(libc::EBADF),
                    }
                };
                let attr = PathAttr {
                    allowed_access: rule.2,
                    parent_fd,
                };
                unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1u32, &attr, 0u32) }
            }
            Step::Restrict => unsafe {
                libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32)
            },
            Step::Seccomp => {
                let filter = libc::sock_fprog {
                    len: prepared.filters.len() as u16,
                    filter: prepared.filters.as_ptr().cast_mut(),
                };
                unsafe {
                    libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter)
                        as libc::c_long
                }
            }
        };
        if answer < 0 {
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(())
        }
    });
    if ruleset >= 0 {
        unsafe { libc::close(ruleset) };
    }
    result
}

pub(super) fn prepare_path_allow(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    plan: landlock_plan::Plan,
) -> Result<Prepared, String> {
    if plan.root_dev.len() != plan.root_ino.len() {
        return Err("provider start is refused: a path root has no identity".into());
    }
    // Each helper's filter comes from the admitted grant. Did's list is not reused.
    if !matches!(
        provider,
        RuntimeProviderId::Localhost | RuntimeProviderId::Object | RuntimeProviderId::Chain
    ) {
        return Err(
            "provider start is refused: the path allow-list filter is only for localhost, object, and chain"
                .into(),
        );
    }
    assemble(provider, admitted, plan)
}

#[cfg(test)]
mod tests {
    use super::super::super::{path_allow, root_pin};
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    fn helper_grant(provider: RuntimeProviderId) -> super::super::super::rights::AdmittedRights {
        super::super::super::rights::admit_runtime_grant(provider)
    }

    fn bindings_for(root: &Path, executable: &Path) -> landlock_plan::Bindings {
        let meta = std::fs::symlink_metadata(root).unwrap();
        landlock_plan::Bindings {
            storage_root: root.to_path_buf(),
            provider_executable: executable.to_path_buf(),
            storage_dev: meta.dev(),
            storage_ino: meta.ino(),
        }
    }

    #[test]
    fn fixed_failure_record_preserves_step_index_and_errno() {
        for (step, errno) in [
            (Step::CloseRange, libc::EBADF),
            (Step::Create, libc::EINVAL),
            (Step::Add(3), libc::EACCES),
            (Step::NoNewPrivileges, libc::EPERM),
            (Step::Restrict, libc::ENOENT),
            (Step::Seccomp, libc::E2BIG),
        ] {
            let failure = Failure(step, errno);
            let record = failure.record();
            let tag = u32::from_ne_bytes(record[..4].try_into().unwrap());
            let index = u32::from_ne_bytes(record[4..8].try_into().unwrap());
            let observed = i32::from_ne_bytes(record[8..].try_into().unwrap());
            assert_eq!(Failure::from_record(tag, index, observed), Some(failure));
        }
    }

    #[test]
    fn installed_child_closes_fds_and_denies_outside_file_and_socket() {
        landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        let root = tempfile::tempdir().unwrap();
        let allowed_path = root.path().join("allowed");
        std::fs::write(&allowed_path, b"ok").unwrap();
        let allowed_path = CString::new(allowed_path.as_os_str().as_bytes()).unwrap();
        let marker = std::fs::File::open("/dev/null").unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        let upper_marker = std::fs::File::open("/dev/null").unwrap();
        assert!(report.as_raw_fd() > 3);
        assert!(upper_marker.as_raw_fd() > report.as_raw_fd());
        let admitted = super::super::super::rights::admit_runtime_grant(RuntimeProviderId::Did);
        let prepared = prepare(
            RuntimeProviderId::Did,
            &admitted,
            &bindings_for(root.path(), Path::new("/bin/true")),
        )
        .unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { install(&prepared, report.as_raw_fd(), -1) }.is_err() {
                unsafe { libc::_exit(80) };
            }
            let kept_open = unsafe { libc::close(report.as_raw_fd()) } == 0;
            let fd_closed = unsafe { libc::close(marker.as_raw_fd()) } == -1
                && unsafe { *libc::__errno_location() } == libc::EBADF;
            let upper_fd_closed = unsafe { libc::close(upper_marker.as_raw_fd()) } == -1
                && unsafe { *libc::__errno_location() } == libc::EBADF;
            let allowed = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    allowed_path.as_ptr(),
                    libc::O_RDONLY,
                )
            };
            let file_allowed = allowed >= 0;
            if file_allowed {
                unsafe { libc::close(allowed as i32) };
            }
            let outside = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/passwd".as_ptr(),
                    libc::O_RDONLY,
                )
            };
            let file_denied = outside == -1 && unsafe { *libc::__errno_location() } == libc::EACCES;
            let socket =
                unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) };
            let socket_denied =
                socket == -1 && unsafe { *libc::__errno_location() } == libc::EACCES;
            unsafe {
                libc::_exit(
                    if kept_open
                        && fd_closed
                        && upper_fd_closed
                        && file_allowed
                        && file_denied
                        && socket_denied
                    {
                        0
                    } else {
                        81
                    },
                )
            };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "child install or confinement probe failed with wait status {status}"
        );
    }

    fn order() -> [Step; 7] {
        [
            Step::CloseRange,
            Step::Create,
            Step::Add(0),
            Step::Add(1),
            Step::NoNewPrivileges,
            Step::Restrict,
            Step::Seccomp,
        ]
    }

    #[test]
    fn every_step_applies_in_order() {
        let mut seen = Vec::new();
        sequence(2, |step| {
            seen.push(step);
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, order());
    }

    fn refusal(failed: Step, expected: &str) {
        let mut seen = Vec::new();
        let error = sequence(2, |step| {
            seen.push(step);
            if step == failed {
                Err(22)
            } else {
                Ok(())
            }
        })
        .expect_err("the failed step must refuse the launch");
        assert_eq!(error.to_string(), expected, "{failed:?}");
        let position = order().iter().position(|step| *step == failed).unwrap();
        assert_eq!(seen, order()[..=position], "{failed:?} must stop here");
    }

    #[test]
    fn close_range_refusal() {
        refusal(
            Step::CloseRange,
            "the probe child could not close inherited descriptors: errno 22",
        );
    }
    #[test]
    fn no_new_privileges_refusal() {
        refusal(
            Step::NoNewPrivileges,
            "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno 22",
        );
    }
    #[test]
    fn create_ruleset_refusal() {
        refusal(
            Step::Create,
            "landlock install refused: the ruleset could not be created with errno 22",
        );
    }
    #[test]
    fn add_rule_refusal() {
        refusal(
            Step::Add(0),
            "landlock install refused: the path rule 0 could not be added with errno 22",
        );
    }
    #[test]
    fn restrict_self_refusal() {
        refusal(
            Step::Restrict,
            "landlock install refused: landlock_restrict_self failed with errno 22",
        );
    }
    #[test]
    fn seccomp_refusal() {
        refusal(
            Step::Seccomp,
            "seccomp install refused: the filter install failed with errno 22",
        );
    }

    /// Install, then open `path` and exit with that errno. Exit 91 when
    /// install itself fails. Exit 0 when the open succeeds.
    #[cfg(target_os = "linux")]
    fn install_then_open(prepared: &Prepared, path: &std::ffi::CStr) -> i32 {
        let report = std::fs::File::open("/dev/null").unwrap();
        assert!(report.as_raw_fd() >= 3);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { install(prepared, report.as_raw_fd(), -1) }.is_err() {
                unsafe { libc::_exit(91) };
            }
            let opened = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            let code = if opened >= 0 {
                unsafe { libc::close(opened) };
                0
            } else {
                unsafe { *libc::__errno_location() }
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        libc::WEXITSTATUS(status)
    }

    #[cfg(target_os = "linux")]
    fn chain_prepared(data: &Path) -> (super::Prepared, usize) {
        let abi = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        std::fs::create_dir(data.join("identity")).unwrap();
        std::fs::create_dir(data.join("chain-provider")).unwrap();
        let executable_path = data.join("helper-provider");
        std::fs::write(&executable_path, b"helper").unwrap();
        std::fs::set_permissions(&executable_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let executable = executable_path.as_path();
        let admitted = helper_grant(RuntimeProviderId::Chain);
        let (_confinement, plan) = path_allow::render_with_plan(
            RuntimeProviderId::Chain,
            &admitted,
            data,
            executable,
            abi,
        )
        .unwrap_or_else(|err| panic!("render before the swap: {err}"));
        assert_eq!(plan.handled, landlock_plan::handled_fs(plan.abi));
        let root_index = plan
            .rules
            .iter()
            .position(|rule| rule.0 == "chain-provider")
            .expect("chain root");
        assert_eq!(
            root_index, 0,
            "the chain root is the first rule, so a refusal here is before any rule is loaded"
        );
        let prepared = prepare_path_allow(RuntimeProviderId::Chain, &admitted, plan).unwrap();
        (prepared, root_index)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer() {
        assert_eq!(
            root_pin::DIRECTORY_OPEN_FLAGS,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            "Linux pinned roots are opened with O_PATH|O_NOFOLLOW|O_DIRECTORY"
        );
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let (prepared, _root_index) = chain_prepared(data);
        let root = data.join("chain-provider");
        std::fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(data.join("identity"), &root).unwrap();
        std::fs::write(data.join("identity").join("device.key"), b"device-key").unwrap();
        let key = data.join("identity").join("device.key");
        let key_c = std::ffi::CString::new(key.as_os_str().as_bytes()).unwrap();
        let code = install_then_open(&prepared, &key_c);
        assert_eq!(
            code,
            libc::EACCES,
            "the held directory is the original root, so the symlink target stays unreadable (exit {code})"
        );
        assert_eq!(std::fs::read(&key).unwrap(), b"device-key");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_different_directory_swapped_in_at_the_same_name_is_refused_with_estale() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let (prepared, root_index) = chain_prepared(data);
        let root = data.join("chain-provider");
        let other = data.join("other-directory");
        std::fs::create_dir(&other).unwrap();
        let aside = data.join("aside-root");
        std::fs::rename(&root, &aside).unwrap();
        std::fs::rename(&other, &root).unwrap();
        let swapped = std::fs::symlink_metadata(&root).unwrap();
        assert_ne!(
            (
                prepared.plan.root_dev[root_index],
                prepared.plan.root_ino[root_index]
            ),
            (swapped.dev(), swapped.ino()),
            "the renamed directory is a different directory"
        );
        let canary = root.join("canary.txt");
        std::fs::write(&canary, b"swapped-directory").unwrap();
        let canary_c = std::ffi::CString::new(canary.as_os_str().as_bytes()).unwrap();
        let code = install_then_open(&prepared, &canary_c);
        assert_eq!(
            code,
            libc::EACCES,
            "the held descriptor is the original directory, so the directory swapped in at the same name stays unreadable (exit {code})"
        );
        assert_eq!(std::fs::read(&canary).unwrap(), b"swapped-directory");
    }

    /// The executable rule is the descriptor held at the check. Replacing the
    /// helper path with a symlink to the data directory does not grant that
    /// directory, so the child cannot read identity/device.key.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_helper_path_swapped_for_a_symlink_does_not_grant_device_key() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        std::fs::create_dir(data.join("identity")).unwrap();
        let key = data.join("identity").join("device.key");
        std::fs::write(&key, b"device-key").unwrap();
        for name in ["ElastOS", "Users", "UsersAI"] {
            std::fs::create_dir(data.join(name)).unwrap();
        }
        let helper = data.join("object-provider");
        std::fs::write(&helper, b"helper").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let abi = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        let admitted = helper_grant(RuntimeProviderId::Object);
        let (_confinement, plan) =
            path_allow::render_with_plan(RuntimeProviderId::Object, &admitted, data, &helper, abi)
                .unwrap_or_else(|err| panic!("render before the swap: {err}"));
        std::fs::remove_file(&helper).unwrap();
        std::os::unix::fs::symlink(data, &helper).unwrap();
        let prepared = prepare_path_allow(RuntimeProviderId::Object, &admitted, plan).unwrap();
        let key_c = std::ffi::CString::new(key.as_os_str().as_bytes()).unwrap();
        let code = install_then_open(&prepared, &key_c);
        assert_eq!(
            code,
            libc::EACCES,
            "a helper path swapped for a symlink to the data folder does not let the child read identity/device.key (exit {code})"
        );
        assert_eq!(std::fs::read(&key).unwrap(), b"device-key");
    }

    /// The loader rule is the descriptor held at the check. Replacing
    /// libc.so.6 after that check does not grant the new file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_loader_replaced_after_the_check_stays_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("loaders");
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root.join("lib"), std::fs::Permissions::from_mode(0o755)).unwrap();
        for name in [
            "ld-linux-x86-64.so.2",
            "ld-linux-aarch64.so.1",
            "ld-musl-x86_64.so.1",
            "ld-musl-aarch64.so.1",
            "libc.so.6",
            "libgcc_s.so.1",
        ] {
            let path = root.join("lib").join(name);
            std::fs::write(&path, b"original-loader").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            std::fs::create_dir(data.join(name)).unwrap();
        }
        let helper = data.join("localhost-provider");
        std::fs::write(&helper, b"helper").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                landlock_plan::set_loader_fixture(None);
            }
        }
        let _clear = Clear;
        landlock_plan::set_loader_fixture(Some((root.clone(), unsafe { libc::geteuid() })));
        let abi = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        let admitted = helper_grant(RuntimeProviderId::Localhost);
        let (_confinement, plan) = path_allow::render_with_plan(
            RuntimeProviderId::Localhost,
            &admitted,
            &data,
            &helper,
            abi,
        )
        .unwrap_or_else(|err| panic!("render: {err}"));
        let libc_path = plan
            .rules
            .iter()
            .find(|rule| rule.0 == "LANDLOCK_LOADER_PATHS" && rule.1.ends_with("libc.so.6"))
            .map(|rule| rule.1.clone())
            .expect("libc.so.6 is a held loader");
        let aside = libc_path.with_file_name("libc.so.6.aside");
        std::fs::rename(&libc_path, &aside).unwrap();
        std::fs::write(&libc_path, b"replaced-loader").unwrap();
        std::fs::set_permissions(&libc_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let prepared = prepare_path_allow(RuntimeProviderId::Localhost, &admitted, plan).unwrap();
        let libc_c = std::ffi::CString::new(libc_path.as_os_str().as_bytes()).unwrap();
        let code = install_then_open(&prepared, &libc_c);
        assert_eq!(
            code,
            libc::EACCES,
            "the held loader descriptor is the original libc, so the file swapped in at the same name stays unreadable (exit {code})"
        );
        assert_eq!(std::fs::read(&libc_path).unwrap(), b"replaced-loader");
        assert_eq!(std::fs::read(&aside).unwrap(), b"original-loader");
    }

    /// `libc::sock_filter` has no `PartialEq` in libc 0.2.189, so the Linux
    /// target compares the four instruction fields.
    fn sock_words(filters: &[libc::sock_filter]) -> Vec<(u16, u8, u8, u32)> {
        filters
            .iter()
            .map(|insn| (insn.code, insn.jt, insn.jf, insn.k))
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_clean_path_allow_plan_installs_and_allows_its_root_but_not_the_device_key() {
        let abi = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let identity = data.join("identity");
        std::fs::create_dir(&identity).unwrap();
        let key_path = identity.join("device.key");
        std::fs::write(&key_path, b"secret").unwrap();
        let root = data.join("chain-provider");
        std::fs::create_dir(&root).unwrap();
        let allowed_path = root.join("note");
        std::fs::write(&allowed_path, b"ok").unwrap();
        let executable = Path::new("/bin/true");
        let admitted = helper_grant(RuntimeProviderId::Chain);
        let (_confinement, plan) = path_allow::render_with_plan(
            RuntimeProviderId::Chain,
            &admitted,
            data,
            executable,
            abi,
        )
        .unwrap_or_else(|err| panic!("clean render: {err}"));
        assert_eq!(plan.handled, landlock_plan::handled_fs(abi));
        let prepared = prepare_path_allow(RuntimeProviderId::Chain, &admitted, plan).unwrap();
        let chain_filter = super::to_sock_filters(super::super::super::seccomp_program::program(
            RuntimeProviderId::Chain,
            &admitted,
            super::host_audit_arch(),
        ))
        .unwrap();
        let did_filter = super::to_sock_filters(super::super::super::seccomp_program::program(
            RuntimeProviderId::Did,
            &helper_grant(RuntimeProviderId::Did),
            super::host_audit_arch(),
        ))
        .unwrap();
        assert_eq!(
            sock_words(&prepared.filters),
            sock_words(&chain_filter),
            "the chain allow-list filter is chain's own grant"
        );
        assert_ne!(
            sock_words(&prepared.filters),
            sock_words(&did_filter),
            "the chain allow-list filter is chain's own grant"
        );
        let sendmmsg =
            super::super::super::seccomp_program::number("sendmmsg", super::host_audit_arch())
                .unwrap();
        assert!(
            prepared.filters.iter().any(|insn| insn.k == sendmmsg),
            "chain filter is missing sendmmsg"
        );
        for name in elastos_common::localhost::FILE_BACKED_ROOTS {
            let path = data.join(name);
            if !path.exists() {
                std::fs::create_dir(&path).unwrap();
            }
        }
        let local_grant = helper_grant(RuntimeProviderId::Localhost);
        let (_local, local_plan) = path_allow::render_with_plan(
            RuntimeProviderId::Localhost,
            &local_grant,
            data,
            executable,
            abi,
        )
        .unwrap();
        assert_eq!(local_plan.handled, landlock_plan::handled_fs(abi));
        let local =
            prepare_path_allow(RuntimeProviderId::Localhost, &local_grant, local_plan).unwrap();
        let local_filter = super::to_sock_filters(super::super::super::seccomp_program::program(
            RuntimeProviderId::Localhost,
            &local_grant,
            super::host_audit_arch(),
        ))
        .unwrap();
        assert_eq!(sock_words(&local.filters), sock_words(&local_filter));
        let object_grant = helper_grant(RuntimeProviderId::Object);
        let (_object, object_plan) = path_allow::render_with_plan(
            RuntimeProviderId::Object,
            &object_grant,
            data,
            executable,
            abi,
        )
        .unwrap();
        assert_eq!(object_plan.handled, landlock_plan::handled_fs(abi));
        let object =
            prepare_path_allow(RuntimeProviderId::Object, &object_grant, object_plan).unwrap();
        assert_ne!(
            sock_words(&object.filters),
            sock_words(&local.filters),
            "object and localhost keep separate syscall lists"
        );
        assert!(prepared
            .plan
            .rules
            .iter()
            .any(|rule| rule.0 == "chain-provider"));
        assert!(!prepared.plan.rules.iter().any(|rule| {
            rule.0 == "STORAGE_ROOT" || rule.0 == "identity" || rule.1.ends_with("device.key")
        }));
        let allowed_c = CString::new(allowed_path.as_os_str().as_bytes()).unwrap();
        let key_c = CString::new(key_path.as_os_str().as_bytes()).unwrap();
        let outside = tmp.path().join("outside-fence.txt");
        let outside_c = CString::new(outside.as_os_str().as_bytes()).unwrap();
        let hosts_c = CString::new("/etc/hosts").unwrap();
        let other_c = CString::new("/bin/false").unwrap();
        assert!(
            prepared
                .plan
                .rules
                .iter()
                .any(|rule| rule.0 == "READ_ONLY_FILE" && rule.1.ends_with("hosts")),
            "chain must rule /etc/hosts so truncate of a read-only file can be checked"
        );
        let kept = data.join("ElastOS/kept.txt");
        std::fs::write(&kept, b"kept-from-the-old-home").unwrap();
        std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o640)).unwrap();
        let kept_c = CString::new(kept.as_os_str().as_bytes()).unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        assert!(report.as_raw_fd() >= 3);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if let Err(Failure(step, _)) = unsafe { install(&prepared, report.as_raw_fd(), -1) } {
                let tag = match step {
                    Step::CloseRange => 1,
                    Step::Create => 2,
                    Step::Add(_) => 3,
                    Step::NoNewPrivileges => 4,
                    Step::Restrict => 5,
                    Step::Seccomp => 6,
                };
                unsafe { libc::_exit(160 + tag) };
            }
            let allowed = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    allowed_c.as_ptr(),
                    libc::O_RDONLY,
                )
            };
            if allowed >= 0 {
                unsafe { libc::close(allowed as i32) };
            }
            let key = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    key_c.as_ptr(),
                    libc::O_RDONLY,
                )
            };
            let key_errno = unsafe { *libc::__errno_location() };
            let code = if allowed < 0 {
                81
            } else if key >= 0 {
                82
            } else if key_errno == libc::EACCES {
                0
            } else if key_errno == 0 {
                84
            } else {
                key_errno
            };
            if code != 0 {
                unsafe { libc::_exit(code) };
            }
            let outside_fd = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    outside_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o644,
                )
            };
            let outside_errno = unsafe { *libc::__errno_location() };
            if outside_fd >= 0 {
                unsafe { libc::close(outside_fd as i32) };
                unsafe { libc::_exit(83) };
            }
            if outside_errno != libc::EACCES {
                unsafe { libc::_exit(83) };
            }
            let hosts = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    hosts_c.as_ptr(),
                    libc::O_RDONLY,
                )
            };
            if hosts < 0 {
                unsafe { libc::_exit(88) };
            }
            unsafe { libc::close(hosts as i32) };
            let trunc = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    hosts_c.as_ptr(),
                    libc::O_RDONLY | libc::O_TRUNC,
                )
            };
            let trunc_errno = unsafe { *libc::__errno_location() };
            if trunc >= 0 {
                unsafe { libc::close(trunc as i32) };
                unsafe { libc::_exit(85) };
            }
            if trunc_errno != libc::EACCES {
                unsafe { libc::_exit(85) };
            }
            let mut argv = [other_c.as_ptr(), std::ptr::null()];
            let mut envp = [std::ptr::null::<libc::c_char>()];
            let exec = unsafe {
                libc::syscall(
                    libc::SYS_execve,
                    other_c.as_ptr(),
                    argv.as_mut_ptr(),
                    envp.as_mut_ptr(),
                )
            };
            if exec >= 0 || unsafe { *libc::__errno_location() } != libc::EACCES {
                unsafe { libc::_exit(86) };
            }
            let again = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    allowed_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if again < 0 {
                unsafe { libc::_exit(81) };
            }
            let mut window = 0i32;
            let ioctl =
                unsafe { libc::syscall(libc::SYS_ioctl, again, libc::FIONREAD, &mut window) };
            let ioctl_errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(again as i32) };
            if ioctl >= 0 || ioctl_errno != libc::EACCES {
                unsafe { libc::_exit(87) };
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "a clean fence plan must install (wait status {status}, exit {}, signal {}): 81 allowed open failed, 82 device key was readable, 83 write outside was not EACCES, 85 truncate of /etc/hosts was not EACCES, 86 exec of /bin/false was not EACCES, 87 ioctl was not EACCES, 88 read of /etc/hosts failed, 161 close_range, 162 create, 163 add, 164 no_new_privs, 165 restrict, 166 seccomp, any other exit is the device-key errno",
            libc::WEXITSTATUS(status),
            if libc::WIFSIGNALED(status) {
                libc::WTERMSIG(status)
            } else {
                0
            },
        );
        let kept_pid = unsafe { libc::fork() };
        assert!(kept_pid >= 0);
        if kept_pid == 0 {
            if unsafe { install(&local, report.as_raw_fd(), -1) }.is_err() {
                unsafe { libc::_exit(89) };
            }
            let opened = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    kept_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            unsafe { libc::_exit(if opened >= 0 { 0 } else { 90 }) };
        }
        let mut kept_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(kept_pid, &mut kept_status, 0) },
            kept_pid
        );
        assert_eq!(
            kept_status, 0,
            "localhost plan must open an existing ElastOS/kept.txt (exit 89 install failed, exit 90 open failed, status {kept_status})"
        );
    }

    /// A copied tree under the test root, found through an injected directory
    /// list that is not the multiarch directory. This child installs that one
    /// file rule. The installer's signature stays the entry's.
    #[test]
    fn a_linux_child_opens_a_library_found_outside_the_multiarch_directory() {
        let root = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let arch = landlock_plan::LoaderArch::host();
        let names: &[&str] = if cfg!(target_arch = "x86_64") {
            &["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]
        } else {
            &["ld-linux-aarch64.so.1", "libc.so.6", "libgcc_s.so.1"]
        };
        let mut paths = Vec::new();
        for name in names {
            paths.push(plant_library(root.path(), &format!("/lib/{name}")));
        }
        let got = landlock_plan::resolve_loader_paths(
            RuntimeProviderId::Localhost,
            arch,
            root.path(),
            Some(&["/lib"]),
            uid,
        )
        .unwrap();
        let got_paths: Vec<_> = got.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(got_paths, paths);
        assert!(got_paths
            .iter()
            .all(|path| !path.to_string_lossy().contains("linux-gnu")));
        let abi = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        let admitted = helper_grant(RuntimeProviderId::Localhost);
        let plan = landlock_plan::Plan {
            abi,
            handled: landlock_plan::handled_fs(abi),
            rules: got
                .files
                .iter()
                .map(|file| {
                    landlock_plan::PathRule(
                        "LANDLOCK_LOADER_PATHS",
                        file.path.clone(),
                        landlock_plan::BINARY,
                    )
                })
                .collect(),
            storage_dev: 0,
            storage_ino: 0,
            root_dev: Vec::new(),
            root_ino: Vec::new(),
            file_pins: got
                .files
                .iter()
                .map(|file| file.pinned.then_some((file.dev, file.ino)))
                .collect(),
            omitted_libraries: got.omitted,
            held: got.files.into_iter().map(|file| file.held).collect(),
        };
        let prepared = prepare_path_allow(RuntimeProviderId::Localhost, &admitted, plan).unwrap();
        let library = CString::new(got_paths[1].as_os_str().as_bytes()).unwrap();
        let hidden = plant_library(root.path(), "/lib/hidden.so");
        let hidden = CString::new(hidden.as_os_str().as_bytes()).unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        assert!(
            report.as_raw_fd() > 3,
            "the report fd must survive close_range"
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match unsafe { install(&prepared, report.as_raw_fd(), -1) } {
                Err(_) => 80,
                Ok(()) => {
                    // The filter admits openat and answers any other open with
                    // EACCES, the same errno Landlock uses for a missing rule.
                    let allowed =
                        unsafe { libc::openat(libc::AT_FDCWD, library.as_ptr(), libc::O_RDONLY) };
                    let denied =
                        unsafe { libc::openat(libc::AT_FDCWD, hidden.as_ptr(), libc::O_RDONLY) };
                    let denied_errno = unsafe { *libc::__errno_location() };
                    if allowed >= 0 {
                        unsafe { libc::close(allowed) };
                    }
                    if allowed >= 0 && denied < 0 && denied_errno == libc::EACCES {
                        0
                    } else {
                        81
                    }
                }
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status}"
        );
    }

    fn plant_library(root: &Path, rel: &str) -> std::path::PathBuf {
        let path = root.join(rel.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"library").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}
