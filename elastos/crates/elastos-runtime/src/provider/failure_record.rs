//! Fixed child install report. All allocation and path preparation finish before fork.
#![allow(dead_code)] // The server does not call this launcher yet.

use super::super::CheckedExecutable;
use super::super::{landlock_plan, rights::AdmittedRights, rights_table::RuntimeProviderId};
use super::preexec_installer;
use std::{
    ffi::{CStr, CString},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    os::unix::fs::MetadataExt,
    path::Path,
};

#[cfg(test)]
thread_local! {
    static PRE_FORK_STORAGE_SWAP: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The next Linux start renames `canary` onto the storage root after the plan
/// has recorded that directory's device and inode and before the child opens it.
#[cfg(test)]
fn set_pre_fork_storage_swap(canary: Option<std::path::PathBuf>) {
    PRE_FORK_STORAGE_SWAP.with(|slot| *slot.borrow_mut() = canary);
}

#[cfg(test)]
fn apply_pre_fork_storage_swap(storage_root: &Path) {
    let Some(canary) = PRE_FORK_STORAGE_SWAP.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    let name = storage_root
        .file_name()
        .expect("the swapped storage root has a name");
    let aside = storage_root.with_file_name(format!("{}.validated", name.to_string_lossy()));
    std::fs::rename(storage_root, &aside).expect("the validated root moves aside");
    std::fs::rename(&canary, storage_root).expect("the canary takes the storage root path");
}

/// Production starts leave the opened directory in place.
#[cfg(not(test))]
fn apply_pre_fork_storage_swap(_storage_root: &Path) {}

const RECORD_LEN: usize = 12;
const EXEC_TAG: u32 = 7;
const DUP2_TAG: u32 = 8;

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestReport {
    Normal,
    NoRecordAfterDelay,
    ShortRecord,
}

#[cfg(test)]
type TestHook = TestReport;
#[cfg(not(test))]
type TestHook = ();

#[cfg(test)]
const NORMAL_TEST_HOOK: TestHook = TestReport::Normal;
#[cfg(not(test))]
const NORMAL_TEST_HOOK: TestHook = ();

#[derive(Debug)]
pub(super) enum LaunchError {
    BeforeFork(String),
    ChildFailed { pid: libc::pid_t, reason: String },
}

/// The successful PID belongs to the caller. Failed children belong to this function.
pub(super) fn start(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    checked: super::CheckedDirectory<'_>,
    executable: &CheckedExecutable,
    args: &[&CStr],
    stdin_read: Option<i32>,
    stdout_write: Option<i32>,
    local_files: &elastos_common::model_landlock_files::LocalModelFiles,
) -> Result<libc::pid_t, LaunchError> {
    let _path = CString::new(executable.path().as_os_str().as_bytes()).map_err(|_| {
        LaunchError::BeforeFork(
            "landlock probe refused: PROVIDER_EXECUTABLE path contains NUL".into(),
        )
    })?;
    let (dev, ino) = directory_identity(checked.path).map_err(LaunchError::BeforeFork)?;
    if dev != checked.dev || ino != checked.ino {
        return Err(LaunchError::BeforeFork(
            "provider start is refused: the reopened storage root is not the checked directory"
                .to_string(),
        ));
    }
    let storage = landlock_plan::StorageRoot {
        path: checked.path,
        dev,
        ino,
    };
    let prepared = preexec_installer::prepare(
        provider,
        admitted,
        &landlock_plan::Bindings {
            storage_root: storage.path.to_path_buf(),
            provider_executable: executable.path().to_path_buf(),
            storage_dev: storage.dev,
            storage_ino: storage.ino,
            local_files: local_files.clone(),
        },
    )
    .map_err(LaunchError::BeforeFork)?;
    // A test may replace the opened directory after its identity is in the plan.
    apply_pre_fork_storage_swap(storage.path);
    launch(
        &prepared,
        executable,
        args,
        NORMAL_TEST_HOOK,
        stdin_read,
        stdout_write,
        None,
    )
}

/// Start a child whose Landlock plan and seccomp filter are already prepared.
/// `data_dir` is one `ELASTOS_DATA_DIR=...` entry. The single-root launcher
/// passes none.
pub(super) fn start_prepared(
    prepared: &preexec_installer::Prepared,
    executable: &CheckedExecutable,
    stdin_read: Option<i32>,
    stdout_write: Option<i32>,
    data_dir: Option<&CStr>,
) -> Result<libc::pid_t, LaunchError> {
    launch(
        prepared,
        executable,
        &[],
        NORMAL_TEST_HOOK,
        stdin_read,
        stdout_write,
        data_dir,
    )
}

fn directory_identity(path: &Path) -> Result<(u64, u64), String> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "provider start is refused: the storage root path contains NUL".to_string())?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "provider start is refused: the storage root could not be opened: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { std::fs::File::from(OwnedFd::from_raw_fd(fd)) };
    let meta = file.metadata().map_err(|error| {
        format!("provider start is refused: the storage root could not be stated: {error}")
    })?;
    Ok((meta.dev(), meta.ino()))
}

fn open_dev_null() -> Result<OwnedFd, String> {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "provider start is refused: /dev/null could not be opened: {}",
            std::io::Error::last_os_error()
        ));
    }
    if fd < 3 {
        unsafe { libc::close(fd) };
        return Err(
            "provider start is refused: the standard error descriptor is below fd 3".into(),
        );
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        unsafe { libc::close(fd) };
        return Err(
            "provider start is refused: the standard error descriptor lacks FD_CLOEXEC".into(),
        );
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn launch(
    prepared: &preexec_installer::Prepared,
    executable: &CheckedExecutable,
    args: &[&CStr],
    test_hook: TestHook,
    stdin_read: Option<i32>,
    stdout_write: Option<i32>,
    data_dir: Option<&CStr>,
) -> Result<libc::pid_t, LaunchError> {
    let verified = executable
        .verify_at_spawn()
        .map_err(LaunchError::BeforeFork)?;
    let executable_fd = verified.fd();
    let path = CString::new(executable.path().as_os_str().as_bytes())
        .map_err(|_| LaunchError::BeforeFork("provider executable path contains NUL".into()))?;
    let mut argv = Vec::with_capacity(args.len() + 2);
    argv.push(path.as_ptr());
    argv.extend(args.iter().map(|arg| arg.as_ptr()));
    argv.push(std::ptr::null());
    let mut env_words = [std::ptr::null(), std::ptr::null()];
    let envp: &[*const libc::c_char] = if let Some(value) = data_dir {
        env_words[0] = value.as_ptr();
        &env_words
    } else {
        &env_words[1..]
    };
    // A zero-byte pipe only proves that the writer closed. Compare the live
    // child's executable with the requested file before handing out its PID.
    // Self-exec is ambiguous before exec, so fail closed in that case.
    let requested_exe = std::fs::metadata(verified.exec_path())
        .ok()
        .map(|meta| (meta.dev(), meta.ino()));
    let launcher_exe = std::fs::metadata("/proc/self/exe")
        .ok()
        .map(|meta| (meta.dev(), meta.ino()));
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(LaunchError::BeforeFork(format!(
            "provider start is refused: the seccomp install report channel could not open: {}",
            std::io::Error::last_os_error()
        )));
    }
    if pipe[0] < 3 || pipe[1] < 3 {
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(LaunchError::BeforeFork(
            "provider start is refused: the report descriptor is below fd 3".into(),
        ));
    }
    let flags = unsafe { libc::fcntl(pipe[1], libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(LaunchError::BeforeFork(
            "provider start is refused: the report descriptor lacks FD_CLOEXEC".into(),
        ));
    }
    let stderr_null = match open_dev_null() {
        Ok(fd) => fd,
        Err(reason) => {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(LaunchError::BeforeFork(reason));
        }
    };
    let stderr_fd = stderr_null.as_raw_fd();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(LaunchError::BeforeFork(format!(
            "provider start is refused: fork failed: {error}"
        )));
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe[0]);
        }
        if let Some(fd) = stdin_read {
            if unsafe { libc::dup2(fd, 0) } < 0 {
                write_record_and_exit(
                    pipe[1],
                    &error_record(DUP2_TAG, unsafe { *libc::__errno_location() }),
                );
            }
        }
        if let Some(fd) = stdout_write {
            if unsafe { libc::dup2(fd, 1) } < 0 {
                write_record_and_exit(
                    pipe[1],
                    &error_record(DUP2_TAG, unsafe { *libc::__errno_location() }),
                );
            }
        }
        // Replace the inherited standard error before confinement. close_range closes this source.
        if unsafe { libc::dup2(stderr_fd, 2) } < 0 {
            write_record_and_exit(
                pipe[1],
                &error_record(DUP2_TAG, unsafe { *libc::__errno_location() }),
            );
        }
        child_test_hook(test_hook, pipe[1]);
        if let Err(failure) =
            unsafe { preexec_installer::install(prepared, pipe[1], executable_fd) }
        {
            write_record_and_exit(pipe[1], &failure.record());
        }
        unsafe {
            // Native providers are ELF files. CLOEXEC closes the verified fd
            // after the kernel enters them, preserving the fd-only child contract.
            libc::fexecve(executable_fd, argv.as_ptr(), envp.as_ptr());
        }
        let errno = unsafe { *libc::__errno_location() };
        write_record_and_exit(pipe[1], &error_record(EXEC_TAG, errno));
    }
    drop(stderr_null);
    unsafe {
        libc::close(pipe[1]);
    }
    let mut bytes = [0u8; RECORD_LEN + 1];
    let mut length = 0;
    let mut read_failure = None;
    loop {
        let read = unsafe {
            libc::read(
                pipe[0],
                bytes[length..].as_mut_ptr().cast(),
                bytes.len() - length,
            )
        };
        if read == 0 {
            break;
        }
        if read < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            read_failure = Some(std::io::Error::last_os_error());
            break;
        }
        length += read as usize;
        if length == bytes.len() {
            break;
        }
    }
    unsafe {
        libc::close(pipe[0]);
    }
    if length == 0 && read_failure.is_none() {
        // CLOEXEC also closes an exec'd child's writer. An exited child may
        // have closed it without ever reporting a failed install or exec.
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == 0 {
                let child_exe = std::fs::metadata(format!("/proc/{pid}/exe"))
                    .ok()
                    .map(|meta| (meta.dev(), meta.ino()));
                if child_exe == requested_exe
                    && requested_exe.is_some()
                    && requested_exe != launcher_exe
                {
                    return Ok(pid);
                }
                // The writer closed before exec, the executable changed, or
                // the child exited while /proc was read. Refuse and own cleanup.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                break;
            }
            if waited == pid {
                return Err(LaunchError::ChildFailed {
                    pid,
                    reason: decode(&[]),
                });
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(LaunchError::ChildFailed {
                    pid,
                    reason: decode(&[]),
                });
            }
        }
        while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        return Err(LaunchError::ChildFailed {
            pid,
            reason: decode(&[]),
        });
    }
    let reason = match read_failure {
        Some(ref error) => {
            format!("seccomp install report refused: the child report could not be read: {error}")
        }
        None => decode(&bytes[..length]),
    };
    let mut status = 0;
    if read_failure.is_some() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    Err(LaunchError::ChildFailed { pid, reason })
}

#[cfg(test)]
fn child_test_hook(hook: TestHook, writer: i32) {
    match hook {
        TestReport::Normal => {}
        TestReport::NoRecordAfterDelay => {
            unsafe { libc::close(writer) };
            let delay = libc::timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            };
            unsafe {
                libc::syscall(
                    libc::SYS_nanosleep,
                    &delay,
                    std::ptr::null::<libc::timespec>(),
                );
                libc::_exit(127)
            }
        }
        TestReport::ShortRecord => unsafe {
            libc::write(writer, b"short".as_ptr().cast(), 5);
            libc::_exit(127)
        },
    }
}

#[cfg(not(test))]
#[inline(always)]
fn child_test_hook(_: TestHook, _: i32) {}

fn error_record(tag: u32, errno: i32) -> [u8; RECORD_LEN] {
    let [t0, t1, t2, t3] = tag.to_ne_bytes();
    let [e0, e1, e2, e3] = errno.to_ne_bytes();
    [t0, t1, t2, t3, 0, 0, 0, 0, e0, e1, e2, e3]
}

/// Only async-signal-safe calls and stack data run here, including on write failure.
fn write_record_and_exit(fd: i32, record: &[u8; RECORD_LEN]) -> ! {
    let mut written = 0;
    while written < RECORD_LEN {
        let count = unsafe {
            libc::write(
                fd,
                record.as_ptr().add(written).cast(),
                RECORD_LEN - written,
            )
        };
        if count < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        }
        if count <= 0 {
            break;
        }
        written += count as usize;
    }
    unsafe { libc::_exit(127) }
}

fn decode(bytes: &[u8]) -> String {
    if bytes.len() != RECORD_LEN {
        return format!("seccomp install report refused: the child reported {} bytes and one record is {RECORD_LEN}", bytes.len());
    }
    let tag = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let index = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let errno = i32::from_ne_bytes(bytes[8..].try_into().unwrap());
    if tag == EXEC_TAG {
        return format!("provider exec refused: execve failed with errno {errno}");
    }
    if tag == DUP2_TAG {
        return format!("provider start is refused: dup2 failed with errno {errno}");
    }
    preexec_installer::Failure::from_record(tag, index, errno)
        .map(|failure| failure.to_string())
        .unwrap_or_else(|| format!("seccomp install report refused: the child named step {tag}, which is no install step"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn did_rows() -> super::super::super::rights::AdmittedRights {
        super::super::super::rights::admit_runtime_grant(RuntimeProviderId::Did)
    }

    fn opened_directory(path: &Path) -> super::super::CheckedDirectory<'_> {
        let (dev, ino) = super::directory_identity(path).expect("the storage root opens");
        super::super::CheckedDirectory { path, dev, ino }
    }

    fn bindings_for(root: &Path, executable: &Path) -> landlock_plan::Bindings {
        let meta = std::fs::symlink_metadata(root).unwrap();
        landlock_plan::Bindings {
            storage_root: root.to_path_buf(),
            provider_executable: executable.to_path_buf(),
            storage_dev: meta.dev(),
            storage_ino: meta.ino(),
            local_files: Default::default(),
        }
    }

    #[test]
    fn refused_before_fork_names_reason() {
        let bad = Path::new(std::ffi::OsStr::from_bytes(b"bad\0path"));
        let rows = did_rows();
        let result = start(
            RuntimeProviderId::Did,
            &rows,
            opened_directory(Path::new("/")),
            &CheckedExecutable::for_test(bad),
            &[],
            None,
            None,
            &elastos_common::model_landlock_files::LocalModelFiles::default(),
        );
        assert!(
            matches!(result, Err(LaunchError::BeforeFork(ref reason)) if reason == "landlock probe refused: PROVIDER_EXECUTABLE path contains NUL")
        );
    }

    #[test]
    fn decoder_refuses_invalid_records_and_names_dup2() {
        for length in [RECORD_LEN - 1, RECORD_LEN + 1] {
            assert_eq!(
                decode(&vec![0; length]),
                format!("seccomp install report refused: the child reported {length} bytes and one record is {RECORD_LEN}")
            );
        }
        assert_eq!(
            decode(&error_record(9, libc::EACCES)),
            "seccomp install report refused: the child named step 9, which is no install step"
        );
        assert_eq!(
            decode(&error_record(DUP2_TAG, libc::EBADF)),
            "provider start is refused: dup2 failed with errno 9"
        );
    }

    #[test]
    fn installer_failure_crosses_pipe_and_child_is_reaped() {
        let root = tempfile::tempdir().unwrap();
        let bindings = bindings_for(root.path(), Path::new("/bin/true"));
        let rows = did_rows();
        let expected_rule = landlock_plan::build(
            RuntimeProviderId::Did,
            &rows,
            &bindings,
            landlock_plan::kernel_abi().unwrap(),
        )
        .unwrap()
        .rules
        .iter()
        .position(|rule| rule.0 == "STORAGE_ROOT")
        .expect("storage rule");
        let prepared =
            preexec_installer::prepare(RuntimeProviderId::Did, &rows, &bindings).unwrap();
        std::fs::remove_dir(root.path()).unwrap();
        let (pid, reason) = match launch(
            &prepared,
            &CheckedExecutable::for_test(Path::new("/bin/true")),
            &[],
            TestReport::Normal,
            None,
            None,
            None,
        ) {
            Err(LaunchError::ChildFailed { pid, reason }) => (pid, reason),
            Ok(pid) => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("the failed installer must refuse the launch");
            }
            other => panic!("the failed installer must refuse the launch: {other:?}"),
        };
        assert_eq!(
            reason,
            format!("landlock install refused: the path rule {expected_rule} could not be added with errno 2"),
            "the failed installer must report its step"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1,
            "the failed child must already be reaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn exec_refusal_crosses_pipe_and_child_is_reaped() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("not-executable");
        std::fs::write(&executable, b"not an executable").unwrap();
        let rows = did_rows();
        let (pid, reason) = match start(
            RuntimeProviderId::Did,
            &rows,
            opened_directory(root.path()),
            &CheckedExecutable::for_test(&executable),
            &[],
            None,
            None,
            &elastos_common::model_landlock_files::LocalModelFiles::default(),
        ) {
            Err(LaunchError::ChildFailed { pid, reason }) => (pid, reason),
            Ok(pid) => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("execve failure must refuse the launch");
            }
            other => panic!("execve failure must refuse the launch: {other:?}"),
        };
        assert_eq!(
            reason, "provider exec refused: execve failed with errno 13",
            "execve failure must cross the report pipe"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1,
            "the exec-refused child must already be reaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_provider_pin_refuses_before_fork() {
        let root = tempfile::tempdir().unwrap();
        let rows = did_rows();
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &rows,
            &bindings_for(root.path(), Path::new("/bin/true")),
        )
        .unwrap();
        let checked = CheckedExecutable::pinned(
            Path::new("/bin/true"),
            &format!("sha256:{}", "0".repeat(64)),
        )
        .unwrap();
        let result = launch(
            &prepared,
            &checked,
            &[],
            TestReport::Normal,
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(LaunchError::BeforeFork(reason))
            if reason == "provider executable differs from verified release checksum"));
    }

    #[test]
    fn child_exits_without_record_is_refused_and_reaped() {
        let root = tempfile::tempdir().unwrap();
        let rows = did_rows();
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &rows,
            &bindings_for(root.path(), Path::new("/bin/true")),
        )
        .unwrap();
        let (pid, reason) = match launch(
            &prepared,
            &CheckedExecutable::for_test(Path::new("/bin/true")),
            &[],
            TestReport::NoRecordAfterDelay,
            None,
            None,
            None,
        ) {
            Err(LaunchError::ChildFailed { pid, reason }) => (pid, reason),
            Ok(pid) => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("a child that exits without a record must be refused");
            }
            other => panic!("a child that exits without a record must be refused: {other:?}"),
        };
        assert_eq!(
            reason,
            "seccomp install report refused: the child reported 0 bytes and one record is 12"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1,
            "the child without a record must already be reaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn short_child_record_is_refused_and_reaped() {
        let root = tempfile::tempdir().unwrap();
        let rows = did_rows();
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &rows,
            &bindings_for(root.path(), Path::new("/bin/true")),
        )
        .unwrap();
        let (pid, reason) = match launch(
            &prepared,
            &CheckedExecutable::for_test(Path::new("/bin/true")),
            &[],
            TestReport::ShortRecord,
            None,
            None,
            None,
        ) {
            Err(LaunchError::ChildFailed { pid, reason }) => (pid, reason),
            other => panic!("a short child record must refuse the launch: {other:?}"),
        };
        assert_eq!(
            reason,
            "seccomp install report refused: the child reported 5 bytes and one record is 12"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn exec_closes_report_and_all_other_descriptors() {
        let root = tempfile::tempdir().unwrap();
        let marker = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&marker), libc::F_SETFD, 0) },
            0
        );
        let rows = did_rows();
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &rows,
            &bindings_for(root.path(), Path::new("/bin/cat")),
        )
        .unwrap();
        let mut input = [-1; 2];
        let mut output = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(input.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(output.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = launch(
            &prepared,
            &CheckedExecutable::for_test(Path::new("/bin/cat")),
            &[],
            TestReport::Normal,
            Some(input[0]),
            Some(output[1]),
            None,
        )
        .unwrap_or_else(|err| panic!("exec must succeed: {err:?}"));
        unsafe {
            libc::close(input[0]);
            libc::close(output[1]);
        }
        assert_eq!(unsafe { libc::write(input[1], b"x".as_ptr().cast(), 1) }, 1);
        let mut reply = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(output[0], reply.as_mut_ptr().cast(), 1) },
            1,
            "the exec'd child must answer through fd 1"
        );
        assert_eq!(reply, *b"x");
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let stderr = std::fs::read_link(format!("/proc/{pid}/fd/2")).unwrap_or_default();
        assert_eq!(
            stderr,
            Path::new("/dev/null"),
            "the confined child standard error is /dev/null"
        );
        unsafe {
            libc::close(input[1]);
            libc::close(output[0]);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            fds.iter().all(|fd| *fd <= 2),
            "the exec'd child must see only fds 0-2: {fds:?}; marker {}",
            std::os::fd::AsRawFd::as_raw_fd(&marker)
        );
        assert_eq!(status, 0);
    }

    #[test]
    fn swapped_storage_root_refuses_and_leaves_the_canary() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let canary = temp.path().join("canary");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&canary).unwrap();
        std::fs::write(canary.join("kept"), b"kept").unwrap();
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rows = did_rows();
        let abi =
            landlock_plan::kernel_abi().expect("Landlock ABI 5 is required for this kernel row");
        let index = landlock_plan::build(
            RuntimeProviderId::Did,
            &rows,
            &bindings_for(&root, Path::new("/bin/true")),
            abi,
        )
        .unwrap()
        .rules
        .iter()
        .position(|rule| rule.0 == "STORAGE_ROOT")
        .expect("storage rule");
        struct ResetSwap;
        impl Drop for ResetSwap {
            fn drop(&mut self) {
                set_pre_fork_storage_swap(None);
            }
        }
        let _reset = ResetSwap;
        set_pre_fork_storage_swap(Some(canary));
        let result = start(
            RuntimeProviderId::Did,
            &rows,
            opened_directory(&root),
            &CheckedExecutable::for_test(Path::new("/bin/true")),
            &[],
            None,
            None,
            &elastos_common::model_landlock_files::LocalModelFiles::default(),
        );
        let kept = std::fs::read(root.join("kept"))
            .unwrap_or_else(|_| panic!("the canary and its permissions stay unchanged"));
        assert_eq!(
            kept, b"kept",
            "the canary and its permissions stay unchanged"
        );
        let mode = std::fs::symlink_metadata(&root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the canary and its permissions stay unchanged");
        match result {
            Err(LaunchError::ChildFailed { reason, .. }) => {
                assert_eq!(
                    reason,
                    format!(
                        "landlock install refused: the path rule {index} could not be added with errno {}",
                        libc::ESTALE
                    ),
                    "a swapped storage root must refuse"
                );
            }
            Ok(pid) => {
                let mut status = 0;
                unsafe { libc::kill(pid, libc::SIGKILL) };
                while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
                panic!("a swapped storage root must refuse");
            }
            other => panic!("a swapped storage root must refuse: {other:?}"),
        }
    }
}
