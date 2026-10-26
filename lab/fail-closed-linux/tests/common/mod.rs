#![allow(dead_code)]

use fail_closed_linux::landlock;
use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output};
use std::time::{Duration, Instant};

pub const PROVIDERS: [&str; 3] = ["did-provider", "wallet-provider", "model-provider"];

pub fn probe() -> PathBuf {
    let probe = PathBuf::from(env!("FCL_PROBE"));
    assert!(probe.is_file(), "the static probe was not built: {probe:?}");
    probe
}

pub fn launcher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fcl-launch"))
}

/// One provider's directories: a storage root, and a sibling directory with a
/// file the provider must not reach.
pub struct Fixture {
    pub root: PathBuf,
    pub storage: PathBuf,
    pub outside_dir: PathBuf,
    pub outside_file: PathBuf,
    /// Master side of a pty. Keeps the slave node alive for the probe.
    #[allow(dead_code)]
    pub tty_master: File,
    /// Slave path (`/dev/pts/N`). Opened after confine so Landlock can deny ioctl.
    pub tty_path: PathBuf,
}

impl Fixture {
    pub fn new(test: &str, provider: &str) -> Fixture {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{test}-{provider}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let storage = root.join("storage");
        let outside_dir = root.join("outside");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("secret.txt");
        fs::write(&outside_file, b"outside the storage root").unwrap();
        let (tty_master, tty_path) = open_pty();
        Fixture {
            root,
            storage,
            outside_dir,
            outside_file,
            tty_master,
            tty_path,
        }
    }

    pub fn marker(&self) -> PathBuf {
        self.storage.join("probe-ran")
    }

    pub fn probe_args(&self, provider: &str) -> Vec<OsString> {
        vec![
            provider.into(),
            self.storage.clone().into(),
            self.outside_file.clone().into(),
            self.outside_dir.clone().into(),
            "--tty-path".into(),
            self.tty_path.clone().into(),
        ]
    }

    /// A copy of the launcher with mode 0111. The kernel marks a process that
    /// runs an unreadable binary as not dumpable, and a process that is not
    /// dumpable cannot open its own /proc/self/uid_map for writing.
    pub fn exec_only_launcher(&self) -> PathBuf {
        let copy = self.root.join("fcl-launch-exec-only");
        fs::copy(launcher(), &copy).unwrap();
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o111)).unwrap();
        copy
    }
}

/// State the launcher inherits from its parent, set up between fork and exec.
pub enum Inherit {
    Nothing,
    /// A seccomp filter that makes one system call fail with `errno`. With
    /// `arg0`, only when the first argument equals it.
    Errno {
        nr: libc::c_long,
        arg0: Option<u32>,
        errno: i32,
    },
    /// A parent user namespace whose `max_user_namespaces` is 0.
    UserNamespaceLimit,
    /// This many stacked Landlock domains that handle only MAKE_BLOCK.
    LandlockDomains(u32),
}

pub fn launch_command(
    launcher: &Path,
    provider: &str,
    fixture: &Fixture,
    options: &[&str],
    inherit: Inherit,
) -> Command {
    let mut command = Command::new(launcher);
    command
        .arg("--provider")
        .arg(provider)
        .arg("--storage-root")
        .arg(&fixture.storage)
        .arg("--readable-path")
        .arg(&fixture.tty_path)
        .args(options)
        .arg("--")
        .arg(probe())
        .args(fixture.probe_args(provider));
    match inherit {
        Inherit::Nothing => {}
        Inherit::Errno { nr, arg0, errno } => {
            let filter = errno_filter(nr, arg0, errno);
            // SAFETY: the closure makes system calls on data built before fork.
            unsafe { command.pre_exec(move || install_inherited_filter(&filter)) };
        }
        Inherit::UserNamespaceLimit => {
            // SAFETY: getuid and getgid cannot fail.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            let uid_map = format!("{uid} {uid} 1\n").into_bytes();
            let gid_map = format!("{gid} {gid} 1\n").into_bytes();
            // SAFETY: the closure makes system calls on data built before fork.
            unsafe {
                command.pre_exec(move || {
                    if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    write_proc(c"/proc/self/uid_map", &uid_map)?;
                    write_proc(c"/proc/self/setgroups", b"deny")?;
                    write_proc(c"/proc/self/gid_map", &gid_map)?;
                    write_proc(c"/proc/sys/user/max_user_namespaces", b"0")
                })
            };
        }
        Inherit::LandlockDomains(count) => {
            // SAFETY: the closure makes system calls on data built before fork.
            unsafe { command.pre_exec(move || stack_landlock_domains(count)) };
        }
    }
    command
}

/// Marks the launcher command so `--test-require-right`,
/// `--test-empty-pipe`, `--test-confine-ready` and `--test-lie-rights`
/// are accepted. Without this env those flags are unknown arguments.
pub fn with_test_hooks(command: &mut Command) -> &mut Command {
    command.env("FCL_TEST_HOOKS", "1")
}

/// Runs the command. Retries while the binary is busy: another test thread
/// may hold a just-copied launcher open between its own fork and exec.
pub fn output(mut command: Command) -> Output {
    for _ in 0..50 {
        match command.output() {
            Err(err) if err.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            result => return result.expect("cannot run the launcher"),
        }
    }
    panic!("the launcher stayed busy");
}

/// A required probe line. A missing line is NOT RUN, never a pass.
pub fn require_line(lines: &[String], prefix: &str, context: &str) -> String {
    lines
        .iter()
        .find(|line| line.starts_with(prefix))
        .cloned()
        .unwrap_or_else(|| {
            panic!("NOT RUN: missing {prefix:?} in {lines:?} ({context})");
        })
}

pub fn wait_with_timeout(child: &mut Child, secs: u64) -> Option<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => return None,
            Err(err) => panic!("wait failed: {err}"),
        }
    }
}

pub fn host_landlock_abi() -> u32 {
    // SAFETY: the version query takes a NULL attribute and size 0.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            landlock::CREATE_RULESET_VERSION,
        )
    };
    assert!(abi > 0, "this host has no Landlock");
    abi as u32
}

/// Checks a launcher run that the guard refused: exit 71, one refusal line
/// naming the provider, layer, step and OS error, and a probe that never ran.
pub fn assert_refused(
    output: &Output,
    fixture: &Fixture,
    provider: &str,
    layer: &str,
    step: &str,
    reason: &str,
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!(
        "status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert_eq!(output.status.code(), Some(71), "{context}");
    let expected = format!("refused to start {provider}: layer {layer}, step {step}: ");
    assert!(
        stderr.contains(&expected),
        "missing {expected:?}\n{context}"
    );
    assert!(stderr.contains(reason), "missing {reason:?}\n{context}");
    assert!(stderr.contains("the provider was not started"), "{context}");
    assert!(!stdout.contains("probe-ran"), "the probe ran\n{context}");
    assert!(
        !stdout.contains("started "),
        "the launcher reported a start\n{context}"
    );
    assert!(
        !fixture.marker().exists(),
        "the probe wrote its marker\n{context}"
    );
}

fn errno_filter(nr: libc::c_long, arg0: Option<u32>, errno: i32) -> Vec<libc::sock_filter> {
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let jeq = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut prog = vec![
        stmt(load, 4),
        jump(jeq, fail_closed_linux::seccomp::AUDIT_ARCH, 1, 0),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
        stmt(load, 0),
    ];
    match arg0 {
        None => prog.push(jump(jeq, nr as u32, 0, 1)),
        Some(arg0) => {
            prog.push(jump(jeq, nr as u32, 0, 3));
            prog.push(stmt(load, 16));
            prog.push(jump(jeq, arg0, 0, 1));
        }
    }
    prog.push(stmt(ret, libc::SECCOMP_RET_ERRNO | errno as u32));
    prog.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
    prog
}

fn install_inherited_filter(filter: &[libc::sock_filter]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: prctl with integer arguments, and a program that outlives the call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn stack_landlock_domains(count: u32) -> io::Result<()> {
    // SAFETY: prctl with integer arguments, and a ruleset attribute that
    // outlives each call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        for _ in 0..count {
            let handled_fs: u64 = landlock::ACCESS_FS_MAKE_BLOCK;
            let fd = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &handled_fs as *const u64,
                std::mem::size_of::<u64>(),
                0u32,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32);
            libc::close(fd as i32);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

pub fn unconfined_tiocgwinsz(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    let mut winsize = [0u16; 4];
    // Linux TIOCGWINSZ. Same number on x86_64 and aarch64.
    const TIOCGWINSZ: u64 = 0x5413;
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), TIOCGWINSZ, winsize.as_mut_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_pty() -> (File, PathBuf) {
    // SAFETY: posix_openpt / grantpt / unlockpt / ptsname_r are the usual pty setup.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt: {}", io::Error::last_os_error());
    assert_eq!(
        unsafe { libc::grantpt(master) },
        0,
        "grantpt: {}",
        io::Error::last_os_error()
    );
    assert_eq!(
        unsafe { libc::unlockpt(master) },
        0,
        "unlockpt: {}",
        io::Error::last_os_error()
    );
    let mut buf = [0u8; 64];
    let ret = unsafe { libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(ret, 0, "ptsname_r: {}", io::Error::last_os_error());
    let path = unsafe { CStr::from_ptr(buf.as_ptr().cast()) }
        .to_str()
        .expect("pts path is UTF-8")
        .to_string();
    // SAFETY: `master` is an open fd we now own.
    let file = unsafe { File::from_raw_fd(master) };
    (file, PathBuf::from(path))
}

fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated; `data` is valid for its length.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let err = io::Error::last_os_error();
        libc::close(fd);
        if written != data.len() as isize {
            return Err(err);
        }
    }
    Ok(())
}
