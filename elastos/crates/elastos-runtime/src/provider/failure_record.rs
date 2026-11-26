//! Fixed child install report. All allocation and path preparation finish before fork.

use super::super::CheckedExecutable;
use super::super::{landlock_plan, rights::AdmittedRights, rights_table::RuntimeProviderId};
use super::preexec_installer;
use std::{
    ffi::{CStr, CString},
    os::fd::{AsRawFd, OwnedFd},
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
) -> Result<libc::pid_t, LaunchError> {
    // The NUL check is the before-fork reason this row names. It runs before
    // the executable check, which refuses a path that cannot be opened.
    let _path = CString::new(executable.path().as_os_str().as_bytes()).map_err(|_| {
        LaunchError::BeforeFork(
            "landlock probe refused: PROVIDER_EXECUTABLE path contains NUL".into(),
        )
    })?;
    let verified = executable
        .verify_at_spawn()
        .map_err(LaunchError::BeforeFork)?;
    let (dev, ino, held) = directory_identity(checked.path).map_err(LaunchError::BeforeFork)?;
    if dev != checked.dev || ino != checked.ino {
        return Err(LaunchError::BeforeFork(
            "provider start is refused: the reopened storage root is not the checked directory"
                .to_string(),
        ));
    }
    landlock_plan::set_checked_directory(held);
    // prepare takes the descriptor on success. An error before that take
    // drops it here, so the thread-local slot does not keep the fd.
    let _clear_checked = ClearCheckedDirectory;
    let storage = landlock_plan::StorageRoot {
        path: checked.path,
        dev,
        ino,
    };
    let prepared = landlock_plan::with_interpreter_fd(verified.fd(), || {
        preexec_installer::prepare(
            provider,
            admitted,
            &landlock_plan::Bindings {
                storage_root: storage.path.to_path_buf(),
                provider_executable: executable.path().to_path_buf(),
                storage_dev: storage.dev,
                storage_ino: storage.ino,
            },
        )
    })
    .map_err(LaunchError::BeforeFork)?;
    // A test may replace the opened directory after its identity is in the plan.
    apply_pre_fork_storage_swap(storage.path);
    let _hold_verified = verified;
    LAUNCH_FD.with(|slot| slot.set(_hold_verified.fd()));
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

fn directory_identity(path: &Path) -> Result<(u64, u64, OwnedFd), String> {
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
    let held = super::super::landlock_plan::owned_fd_above_stdio(fd).map_err(|errno| {
        format!(
            "provider start is refused: the storage root could not be opened: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;
    let file = std::fs::File::from(held);
    let meta = file.metadata().map_err(|error| {
        format!("provider start is refused: the storage root could not be stated: {error}")
    })?;
    Ok((meta.dev(), meta.ino(), OwnedFd::from(file)))
}

thread_local! {
    static LAUNCH_FD: std::cell::Cell<i32> = const { std::cell::Cell::new(-1) };
}

pub(super) fn with_launch_fd<T>(fd: i32, body: impl FnOnce() -> T) -> T {
    LAUNCH_FD.with(|slot| {
        let previous = slot.replace(fd);
        let result = body();
        slot.set(previous);
        result
    })
}

fn open_dev_null() -> Result<OwnedFd, String> {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "provider start is refused: /dev/null could not be opened: {}",
            std::io::Error::last_os_error()
        ));
    }
    let held = super::super::landlock_plan::owned_fd_above_stdio(fd).map_err(|errno| {
        format!(
            "provider start is refused: /dev/null could not be opened: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;
    let fd = held.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        drop(held);
        return Err(
            "provider start is refused: the standard error descriptor lacks FD_CLOEXEC".into(),
        );
    }
    Ok(held)
}

/// Kill an unconfined child and reap it. A deleted `kill` or `waitpid`
/// leaves the child running, and the row that calls this turns red.
/// `ESRCH` means the child is already dead. This still calls `waitpid`:
/// a zombie is not reaped until that call, and `ECHILD` means it was
/// already reaped.
fn reap_unconfined(pid: libc::pid_t) -> bool {
    let mut already_dead = false;
    if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
        let err = std::io::Error::last_os_error().raw_os_error();
        if err != Some(libc::ESRCH) {
            return false;
        }
        already_dead = true;
    }
    let finished = |status: i32| {
        already_dead || (libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL)
    };
    let gone = |err: Option<i32>| already_dead && err == Some(libc::ECHILD);
    for _ in 0..100 {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return finished(status);
        }
        if waited < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
            return gone(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return finished(status);
        }
        if waited < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
            return gone(err);
        }
    }
}

struct ClearCheckedDirectory;

impl Drop for ClearCheckedDirectory {
    fn drop(&mut self) {
        landlock_plan::clear_checked_directory();
    }
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
    // The census reads this call. A launch that already holds the verified
    // descriptor uses that descriptor for the rule and for exec.
    let verified_owned = executable
        .verify_at_spawn()
        .map_err(LaunchError::BeforeFork)?;
    let staged = LAUNCH_FD.with(|slot| slot.replace(-1));
    let executable_fd = if staged >= 0 {
        staged
    } else {
        verified_owned.fd()
    };
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
    let requested_exe = std::fs::metadata(format!("/proc/self/fd/{executable_fd}"))
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
                    let proc_status =
                        std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                    if super::super::landlock_plan::child_confinement_refusal(&proc_status)
                        .is_none()
                    {
                        return Ok(pid);
                    }
                    let reason = super::super::landlock_plan::child_confinement_refusal(&proc_status)
                        .unwrap_or(
                            "provider start is refused: the child is not confined (NoNewPrivs and Seccomp)",
                        )
                        .to_string();
                    if !reap_unconfined(pid) {
                        let mut status = 0;
                        loop {
                            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
                            if waited == pid
                                || (waited < 0
                                    && std::io::Error::last_os_error().raw_os_error()
                                        != Some(libc::EINTR))
                            {
                                break;
                            }
                        }
                    }
                    return Err(LaunchError::ChildFailed { pid, reason });
                }
                // The writer closed before exec, the executable changed, or
                // the child exited while /proc was read. Refuse and own cleanup.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                break;
            }
            if waited == pid {
                return Err(LaunchError::ChildFailed {
                    pid,
                    reason: decode(&[], Some(prepared)),
                });
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(LaunchError::ChildFailed {
                    pid,
                    reason: decode(&[], Some(prepared)),
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
            reason: decode(&[], Some(prepared)),
        });
    }
    let reason = match read_failure {
        Some(ref error) => {
            format!("seccomp install report refused: the child report could not be read: {error}")
        }
        None => decode(&bytes[..length], Some(prepared)),
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

fn decode(bytes: &[u8], prepared: Option<&preexec_installer::Prepared>) -> String {
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
    if tag == 3 {
        if let Some((name, path)) =
            prepared.and_then(|prepared| prepared.added_rule(index as usize))
        {
            return format!(
                "landlock install refused: {name} {} could not be added with errno {errno}",
                path.display()
            );
        }
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

    fn static_elf_header() -> [u8; 64] {
        let mut header = [0u8; 64];
        header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16] = 2;
        header[18] = 0x3e;
        header[20] = 1;
        header[52] = 64;
        header
    }

    fn did_rows() -> super::super::super::rights::AdmittedRights {
        super::super::super::rights::admit_runtime_grant(RuntimeProviderId::Did)
    }

    fn opened_directory(path: &Path) -> super::super::CheckedDirectory<'_> {
        let (dev, ino, _held) = super::directory_identity(path).expect("the storage root opens");
        super::super::CheckedDirectory { path, dev, ino }
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
        );
        assert!(
            matches!(result, Err(LaunchError::BeforeFork(ref reason)) if reason == "landlock probe refused: PROVIDER_EXECUTABLE path contains NUL")
        );
    }

    #[test]
    fn decoder_refuses_invalid_records_and_names_dup2() {
        for length in [RECORD_LEN - 1, RECORD_LEN + 1] {
            assert_eq!(
                decode(&vec![0; length], None),
                format!("seccomp install report refused: the child reported {length} bytes and one record is {RECORD_LEN}")
            );
        }
        assert_eq!(
            decode(&error_record(9, libc::EACCES), None),
            "seccomp install report refused: the child named step 9, which is no install step"
        );
        assert_eq!(
            decode(&error_record(DUP2_TAG, libc::EBADF), None),
            "provider start is refused: dup2 failed with errno 9"
        );
    }

    #[test]
    fn an_add_refusal_names_the_rule_and_its_path() {
        let root = tempfile::tempdir().unwrap();
        let bindings = bindings_for(root.path(), Path::new("/bin/true"));
        let rows = did_rows();
        let prepared =
            preexec_installer::prepare(RuntimeProviderId::Did, &rows, &bindings).unwrap();
        let (name, path) = prepared.added_rule(0).expect("rule 0");
        let text = decode(&error_record(3, libc::EACCES), Some(&prepared));
        assert!(text.contains(name), "{text}");
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(text.contains("could not be added"), "{text}");
    }

    #[test]
    fn an_unconfined_child_is_refused_by_name_and_killed() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let reason = landlock_plan::child_confinement_refusal(&text);
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        let reason = reason.expect("an unconfined child is refused");
        assert!(reason.contains("NoNewPrivs"), "{reason}");
        assert!(reason.contains("Seccomp"), "{reason}");
        assert!(!text.contains("NoNewPrivs:\t1") || !text.contains("Seccomp:\t2"));
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
        let mut prepared =
            preexec_installer::prepare(RuntimeProviderId::Did, &rows, &bindings).unwrap();
        // The child adds the descriptor held at prepare. Removing the
        // directory leaves that descriptor valid, so the add succeeds.
        // Dropping the held descriptor is the installer failure inside the
        // child: errno 9, EBADF, still naming this rule and this path.
        prepared.drop_held_for_test(expected_rule);
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
        let (name, path) = prepared
            .added_rule(expected_rule)
            .expect("the storage rule has a name and a path");
        assert_eq!(
            reason,
            format!(
                "landlock install refused: {name} {} could not be added with errno 9",
                path.display()
            ),
            "the failed installer must name the rule and its path"
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
        // A 64-bit little-endian ELF with no program headers is Static, so
        // the ELF check does not refuse it before fork. Mode 0644 makes
        // fexecve return EACCES (errno 13). The report still crosses the pipe
        // and the child is reaped.
        std::fs::write(&executable, static_elf_header()).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o644)).unwrap();
        let rows = did_rows();
        let (pid, reason) = match start(
            RuntimeProviderId::Did,
            &rows,
            opened_directory(root.path()),
            &CheckedExecutable::for_test(&executable),
            &[],
            None,
            None,
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
        let _ = landlock_plan::kernel_abi().expect("this kernel has no Landlock");
        struct ResetSwap;
        impl Drop for ResetSwap {
            fn drop(&mut self) {
                set_pre_fork_storage_swap(None);
            }
        }
        let _reset = ResetSwap;
        let executable = CheckedExecutable::for_test(Path::new("/bin/true"));
        let verified = executable.verify_at_spawn().expect("/bin/true opens");
        let (_dev, _ino, held) = directory_identity(&root).expect("the storage root opens");
        landlock_plan::set_checked_directory(held);
        let prepared = landlock_plan::with_interpreter_fd(verified.fd(), || {
            preexec_installer::prepare(
                RuntimeProviderId::Did,
                &rows,
                &bindings_for(&root, Path::new("/bin/true")),
            )
        })
        .expect("the single-root plan");
        drop(verified);
        set_pre_fork_storage_swap(Some(canary));
        apply_pre_fork_storage_swap(&root);
        let kept_path = root.join("kept");
        let kept_c = std::ffi::CString::new(kept_path.as_os_str().as_bytes()).unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        assert!(
            std::os::fd::AsRawFd::as_raw_fd(&report) >= 3,
            "the report fd must survive close_range"
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = if unsafe {
                preexec_installer::install(&prepared, std::os::fd::AsRawFd::as_raw_fd(&report), -1)
            }
            .is_err()
            {
                91
            } else {
                let opened = unsafe { libc::open(kept_c.as_ptr(), libc::O_RDONLY) };
                if opened >= 0 {
                    unsafe { libc::close(opened) };
                    0
                } else {
                    unsafe { *libc::__errno_location() }
                }
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            libc::EACCES,
            "the confined child opening root/kept is refused (exit {})",
            libc::WEXITSTATUS(status)
        );
        let kept = std::fs::read(&kept_path)
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
    }

    #[test]
    fn deleting_kill_and_waitpid_leaves_the_unconfined_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        let reaped = reap_unconfined(pid);
        if !reaped {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
        assert!(reaped, "kill and waitpid reap the unconfined child");
        let body = include_str!("failure_record.rs");
        let function = body
            .split("fn reap_unconfined")
            .nth(1)
            .unwrap()
            .split("fn launch")
            .next()
            .unwrap();
        assert!(function.contains("libc::kill"), "the row names kill");
        assert!(function.contains("libc::waitpid"), "the row names waitpid");
        let launch = body.split("fn launch(").nth(1).unwrap();
        let after_accept = launch.split("return Ok(pid)").nth(1).unwrap();
        assert!(
            after_accept.contains("reap_unconfined"),
            "an unconfined child is killed and reaped before its error returns"
        );
    }

    #[test]
    fn reap_unconfined_waits_when_kill_says_esrch() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        // The child is already reaped, so kill returns ESRCH and waitpid
        // returns ECHILD. The reap still calls both.
        assert!(
            reap_unconfined(pid),
            "ESRCH from kill still waits for the child"
        );
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
    fn an_error_before_take_clears_the_checked_directory() {
        let root = tempfile::tempdir().unwrap();
        let (_dev, _ino, held) = directory_identity(root.path()).unwrap();
        landlock_plan::set_checked_directory(held);
        let failed: Result<(), String> = {
            let _clear = ClearCheckedDirectory;
            Err("prepare stopped before take".into())
        };
        assert!(failed.is_err());
        assert!(
            !landlock_plan::checked_directory_is_held(),
            "the directory fd stayed in the thread-local slot"
        );
        let body = include_str!("failure_record.rs");
        let start = body.split("pub(super) fn start(").nth(1).unwrap();
        let start = start.split("pub(super) fn start_prepared").next().unwrap();
        assert!(
            start.contains("ClearCheckedDirectory"),
            "start clears the checked directory when prepare fails"
        );
    }
}
