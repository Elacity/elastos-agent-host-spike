//! Fixed child install report. All allocation and path preparation finish before fork.
#![allow(dead_code)] // The provider spawn binding arrives in a later B3 slice.

use super::{landlock_plan, preexec_installer, rights_table::RuntimeProviderId};
use std::{
    ffi::{CStr, CString},
    os::unix::ffi::OsStrExt,
    path::Path,
};

const RECORD_LEN: usize = 12;

#[derive(Debug)]
enum LaunchError {
    BeforeFork(String),
    ChildFailed { pid: libc::pid_t, reason: String },
}

/// The successful PID belongs to the caller. Failed children belong to this function.
fn start(
    provider: RuntimeProviderId,
    storage_root: &Path,
    executable: &Path,
    args: &[&CStr],
) -> Result<libc::pid_t, LaunchError> {
    let path = CString::new(executable.as_os_str().as_bytes()).map_err(|_| {
        LaunchError::BeforeFork(
            "provider start is refused: the executable path contains NUL".into(),
        )
    })?;
    let prepared = preexec_installer::prepare(
        provider,
        &landlock_plan::Bindings {
            storage_root: storage_root.to_path_buf(),
            provider_executable: executable.to_path_buf(),
        },
    )
    .map_err(LaunchError::BeforeFork)?;
    launch(&prepared, &path, args, None, None, None)
}

fn launch(
    prepared: &preexec_installer::Prepared,
    path: &CStr,
    args: &[&CStr],
    injected: Option<[u8; RECORD_LEN]>,
    stdin_read: Option<i32>,
    stdout_write: Option<i32>,
) -> Result<libc::pid_t, LaunchError> {
    let mut argv = Vec::with_capacity(args.len() + 2);
    argv.push(path.as_ptr());
    argv.extend(args.iter().map(|arg| arg.as_ptr()));
    argv.push(std::ptr::null());
    let envp = [std::ptr::null()];
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(LaunchError::BeforeFork(format!(
            "seccomp install refused: the report pipe could not open: {}",
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
                write_record_and_exit(pipe[1], &exec_record(unsafe { *libc::__errno_location() }));
            }
        }
        if let Some(fd) = stdout_write {
            if unsafe { libc::dup2(fd, 1) } < 0 {
                write_record_and_exit(pipe[1], &exec_record(unsafe { *libc::__errno_location() }));
            }
        }
        if let Some(record) = injected {
            write_record_and_exit(pipe[1], &record);
        }
        if let Err(failure) = unsafe { preexec_installer::install(prepared, pipe[1]) } {
            write_record_and_exit(pipe[1], &failure.record());
        }
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        let errno = unsafe { *libc::__errno_location() };
        write_record_and_exit(pipe[1], &exec_record(errno));
    }
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
        return Ok(pid);
    } // CLOEXEC closed the writer on successful exec.
    let reason = match read_failure {
        Some(error) => {
            format!("seccomp install report refused: the child report could not be read: {error}")
        }
        None => decode(&bytes[..length]),
    };
    let mut status = 0;
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    Err(LaunchError::ChildFailed { pid, reason })
}

fn exec_record(errno: i32) -> [u8; RECORD_LEN] {
    let [e0, e1, e2, e3] = errno.to_ne_bytes();
    [7, 0, 0, 0, 0, 0, 0, 0, e0, e1, e2, e3]
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
    if tag == 7 {
        return format!("provider exec refused: execve failed with errno {errno}");
    }
    preexec_installer::Failure::from_record(tag, index, errno)
        .map(|failure| failure.to_string())
        .unwrap_or_else(|| format!("seccomp install report refused: the child named step {tag}, which is no install step"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn refused_before_fork_names_reason() {
        let bad = Path::new(std::ffi::OsStr::from_bytes(b"bad\0path"));
        let result = start(RuntimeProviderId::Did, Path::new("/"), bad, &[]);
        assert!(
            matches!(result, Err(LaunchError::BeforeFork(ref reason)) if reason == "provider start is refused: the executable path contains NUL")
        );
    }

    #[test]
    fn injected_step_crosses_pipe_and_child_is_reaped() {
        let root = tempfile::tempdir().unwrap();
        let path = CString::new("/bin/true").unwrap();
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &landlock_plan::Bindings {
                storage_root: root.path().to_path_buf(),
                provider_executable: "/bin/true".into(),
            },
        )
        .unwrap();
        let mut record = [0; RECORD_LEN];
        record[..4].copy_from_slice(&3u32.to_ne_bytes());
        record[4..8].copy_from_slice(&1u32.to_ne_bytes());
        record[8..].copy_from_slice(&libc::EACCES.to_ne_bytes());
        let (pid, reason) = match launch(&prepared, &path, &[], Some(record), None, None) {
            Err(LaunchError::ChildFailed { pid, reason }) => (pid, reason),
            Ok(pid) => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                panic!("the injected step must refuse the launch");
            }
            other => panic!("the injected step must refuse the launch: {other:?}"),
        };
        assert_eq!(
            reason,
            "landlock install refused: the path rule 1 could not be added with errno 13"
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
    fn exec_closes_report_and_all_other_descriptors() {
        let root = tempfile::tempdir().unwrap();
        let path = CString::new("/bin/cat").unwrap();
        let marker = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&marker), libc::F_SETFD, 0) },
            0
        );
        let prepared = preexec_installer::prepare(
            RuntimeProviderId::Did,
            &landlock_plan::Bindings {
                storage_root: root.path().to_path_buf(),
                provider_executable: "/bin/cat".into(),
            },
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
        let pid = launch(&prepared, &path, &[], None, Some(input[0]), Some(output[1]))
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
}
