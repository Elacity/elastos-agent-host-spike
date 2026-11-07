#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use fail_closed_linux::{Errno, FsRules, Kernel, Policy, SeccompProgram};

pub const STAND_IN: &str = env!("CARGO_BIN_EXE_stand-in-provider");
pub const FCL_LAUNCH: &str = env!("CARGO_BIN_EXE_fcl-launch");

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("fcl-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Loader and library directories the dynamically linked stand-in reads.
pub fn loader_dirs() -> Vec<PathBuf> {
    ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .collect()
}

/// The policy the tests give the stand-in: its own executable, its storage
/// root, and the loader directories.
pub fn stand_in_policy(storage_root: &Path) -> Policy {
    let mut fs = FsRules::new().exec_file(Path::new(STAND_IN)).unwrap();
    for dir in loader_dirs() {
        fs = fs.read_exec_dir(&dir).unwrap();
    }
    Policy::baseline(fs.read_write_dir(storage_root).unwrap()).unwrap()
}

pub fn marker_of(storage_root: &Path) -> PathBuf {
    storage_root.join("ran")
}

pub fn stand_in_command(storage_root: &Path) -> Command {
    let mut command = Command::new(STAND_IN);
    command
        .arg("--marker")
        .arg(marker_of(storage_root))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    command
}

/// A started stand-in provider and its line protocol.
pub struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Session {
    pub fn new(mut child: Child) -> Session {
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Session {
            child,
            stdin,
            stdout,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn ask(&mut self, line: &str) -> String {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut reply = String::new();
        self.stdout.read_line(&mut reply).unwrap();
        reply.trim().to_string()
    }

    pub fn finish(mut self) {
        let _ = self.ask("exit");
        drop(self.stdin.take());
        self.child.wait().unwrap();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn field(reply: &str, key: &str) -> String {
    reply
        .split_whitespace()
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in {reply:?}"))
        .to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    UnshareUser,
    MapIds,
    DropCapabilities,
    NoNewPrivs,
    Seccomp,
    LandlockAbi,
    LandlockRestrict,
}

impl Call {
    pub const ORDER: [Call; 7] = [
        Call::UnshareUser,
        Call::MapIds,
        Call::DropCapabilities,
        Call::NoNewPrivs,
        Call::Seccomp,
        Call::LandlockAbi,
        Call::LandlockRestrict,
    ];

    fn name(self) -> &'static str {
        match self {
            Call::UnshareUser => "unshare_user\n",
            Call::MapIds => "map_ids\n",
            Call::DropCapabilities => "drop_capabilities\n",
            Call::NoNewPrivs => "no_new_privs\n",
            Call::Seccomp => "seccomp\n",
            Call::LandlockAbi => "landlock_abi\n",
            Call::LandlockRestrict => "landlock_restrict\n",
        }
    }
}

/// A kernel that records each call in a file and fails the calls it is told to.
/// The file is how a forked child reports back to the test.
pub struct SimKernel {
    log: RawFd,
    abi: u32,
    failing: Vec<(Call, Errno)>,
}

impl SimKernel {
    pub fn new(log: &File, abi: u32, failing: &[(Call, Errno)]) -> SimKernel {
        SimKernel {
            log: log.as_raw_fd(),
            abi,
            failing: failing.to_vec(),
        }
    }

    fn hit(&self, call: Call) -> Result<(), Errno> {
        let name = call.name();
        // SAFETY: `write` on a descriptor the test keeps open; async-signal-safe.
        unsafe { libc::write(self.log, name.as_ptr().cast(), name.len()) };
        match self.failing.iter().find(|(failing, _)| *failing == call) {
            Some((_, errno)) => Err(*errno),
            None => Ok(()),
        }
    }
}

impl Kernel for SimKernel {
    fn landlock_abi(&self) -> Result<u32, Errno> {
        self.hit(Call::LandlockAbi).map(|()| self.abi)
    }
    fn unshare_user(&self) -> Result<(), Errno> {
        self.hit(Call::UnshareUser)
    }
    fn map_ids(&self) -> Result<(), Errno> {
        self.hit(Call::MapIds)
    }
    fn drop_capabilities(&self) -> Result<(), Errno> {
        self.hit(Call::DropCapabilities)
    }
    fn set_no_new_privs(&self) -> Result<(), Errno> {
        self.hit(Call::NoNewPrivs)
    }
    fn install_seccomp(&self, _program: &SeccompProgram) -> Result<(), Errno> {
        self.hit(Call::Seccomp)
    }
    fn landlock_restrict(&self, _rules: &FsRules) -> Result<(), Errno> {
        self.hit(Call::LandlockRestrict)
    }
}

pub fn call_log() -> (TempDir, PathBuf, File) {
    let dir = TempDir::new("log");
    let path = dir.path().join("calls");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    (dir, path, file)
}

pub fn read_calls(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

pub fn expected_calls_through(last: Call) -> Vec<String> {
    let end = Call::ORDER.iter().position(|call| *call == last).unwrap();
    Call::ORDER[..=end]
        .iter()
        .map(|call| call.name().trim_end().to_string())
        .collect()
}

// An independent seccomp harness. It does not use the crate's own filter
// builder, so a fault in that builder cannot hide here.

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// A filter that fails `nr` with `errno`; with `arg0`, only when the first
/// argument equals it.
pub fn deny_filter(nr: i64, errno: i32, arg0: Option<u32>) -> Vec<libc::sock_filter> {
    let mut program = vec![
        insn(LD_W_ABS, 0, 0, 4),
        insn(JEQ_K, 1, 0, NATIVE_ARCH),
        insn(RET_K, 0, 0, RET_KILL_PROCESS),
        insn(LD_W_ABS, 0, 0, 0),
    ];
    match arg0 {
        None => program.extend([
            insn(JEQ_K, 0, 1, nr as u32),
            insn(RET_K, 0, 0, RET_ERRNO | errno as u32),
            insn(RET_K, 0, 0, RET_ALLOW),
        ]),
        Some(first) => program.extend([
            insn(JEQ_K, 0, 3, nr as u32),
            insn(LD_W_ABS, 0, 0, 16),
            insn(JEQ_K, 0, 1, first),
            insn(RET_K, 0, 0, RET_ERRNO | errno as u32),
            insn(RET_K, 0, 0, RET_ALLOW),
        ]),
    }
    program
}

/// Make `command`'s child install `filter` before it starts. The child then
/// runs, and passes on, a kernel in which that system call fails.
pub fn install_inherited_filter(command: &mut Command, filter: Vec<libc::sock_filter>) {
    // SAFETY: only `prctl` and `seccomp` run between `fork` and `exec`.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let prog = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut libc::sock_filter,
            };
            if libc::syscall(
                libc::SYS_seccomp,
                1 as libc::c_long,
                0 as libc::c_long,
                &prog as *const libc::sock_fprog,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Run a classic BPF seccomp program on one synthetic `seccomp_data`.
pub fn run_filter(program: &[fail_closed_linux::SockFilter], arch: u32, nr: u32) -> u32 {
    let load = |offset: u32| match offset {
        0 => nr,
        4 => arch,
        other => panic!("filter reads offset {other}"),
    };
    let (mut acc, mut pc) = (0u32, 0usize);
    loop {
        let step = program[pc];
        pc += 1;
        match step.code {
            LD_W_ABS => acc = load(step.k),
            JEQ_K => pc += usize::from(if acc == step.k { step.jt } else { step.jf }),
            0x45 => pc += usize::from(if acc & step.k != 0 { step.jt } else { step.jf }),
            RET_K => return step.k,
            other => panic!("unexpected opcode {other:#x}"),
        }
    }
}

pub const fn native_arch() -> u32 {
    NATIVE_ARCH
}

/// The CLI with its provider arguments and an inherited filter on it.
pub fn launch_cli_under(
    provider: &str,
    storage_root: &Path,
    filter: Option<Vec<libc::sock_filter>>,
) -> Command {
    let mut command = Command::new(FCL_LAUNCH);
    command
        .arg("--provider")
        .arg(provider)
        .arg("--storage-root")
        .arg(storage_root);
    for dir in loader_dirs() {
        command.arg("--read-exec").arg(dir);
    }
    command
        .arg("--")
        .arg(STAND_IN)
        .arg("--marker")
        .arg(marker_of(storage_root));
    if let Some(filter) = filter {
        install_inherited_filter(&mut command, filter);
    }
    command
}
