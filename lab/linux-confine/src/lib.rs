//! Linux enforcement of the three provider confinement profiles.
//!
//! The seatbelt files stay the oracle. This crate maps each of them onto one
//! launch: a user namespace, empty capabilities, a Landlock ruleset, and a
//! seccomp allow-list. The freestanding probe checks that filter with no
//! libraries. A provider launch execs a shipping binary and adds only the
//! read and execute paths `ldd` names for that binary.

#![forbid(unsafe_code)]

mod policy;
mod profile;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use policy::deny_network_by_default;
pub use profile::{allow_rules, parse_profile, Allow, Profile};

pub const NO_LANDLOCK: &str = "linux confinement refused: the kernel has no Landlock";
pub const NO_SECCOMP: &str = "linux confinement refused: the kernel has no seccomp";
pub const ABI_STORAGE: &str =
    "linux confinement refused: the Landlock ABI cannot express the STORAGE_ROOT read and write";
pub const ABI_IOCTL: &str =
    "linux confinement refused: the Landlock ABI cannot express device ioctl";
pub const NO_USERNS: &str = "linux confinement refused: user namespaces are turned off";

/// `STORAGE_ROOT` Landlock mask. Read file, read directory, write file,
/// truncate, make a regular file, make a directory, remove a file, remove a
/// directory. Device, socket, fifo, symlink, refer, and device ioctl stay off.
pub const STORAGE_ROOT_RIGHTS: u64 = 0x41be;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub op: String,
    pub result: String,
    pub errno: Option<i32>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enforced {
    pub abi: i32,
    pub uid: i32,
    pub caps: String,
    pub nnp: i32,
    pub netns: String,
    pub storage_rights: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub enforced: Enforced,
    pub ops: Vec<Op>,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Launch {
    pub deny_network: bool,
    pub storage_root: PathBuf,
    pub storage: PathBuf,
    pub storage2: Option<PathBuf>,
    pub outside: PathBuf,
    pub parent: PathBuf,
    pub copy: PathBuf,
    /// Install the provider seccomp filter, then still exec the freestanding
    /// probe with the check arguments. The shipping `mode=provider` path execs
    /// a provider binary instead.
    pub provider_filter: bool,
}

pub fn explain_abi(abi: i32) -> Result<String, String> {
    run_test(&["--explain-abi".to_string(), abi.to_string()])
}

pub fn block_landlock() -> Result<String, String> {
    run_test(&["--block-landlock".to_string()])
}

pub fn block_seccomp() -> Result<String, String> {
    run_test(&["--block-seccomp".to_string()])
}

pub fn block_userns(launch: &Launch) -> Result<String, String> {
    let policy = write_policy(launch)?;
    run_test(&["--block-userns".to_string(), policy.display().to_string()])
}

pub fn launch(launch: &Launch) -> Result<Report, String> {
    let policy = write_policy(launch)?;
    let raw = run(&[policy.display().to_string()])?;
    parse_report(&raw).map_err(|err| format!("{err}\n{raw}"))
}

fn write_policy(launch: &Launch) -> Result<PathBuf, String> {
    let parent = launch
        .storage_root
        .parent()
        .ok_or("the storage root has no parent")?;
    let path = parent.join("launch.policy");
    let storage2 = launch
        .storage2
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "-".to_string());
    let body = format!(
        "deny_network={}\nfilter={}\nhelper={}\nstorage_root={}\nstorage={}\nstorage2={}\noutside={}\nparent={}\ncopy={}\n",
        if launch.deny_network { "1" } else { "0" },
        if launch.provider_filter {
            "provider"
        } else {
            "probe"
        },
        env_bin("LC_PROBE"),
        launch.storage_root.display(),
        launch.storage.display(),
        storage2,
        launch.outside.display(),
        launch.parent.display(),
        launch.copy.display(),
    );
    fs::write(&path, body).map_err(|err| format!("cannot write policy: {err}"))?;
    Ok(path)
}

fn env_bin(key: &str) -> &'static str {
    match key {
        "LC_PROBE" => env!("LC_PROBE"),
        "LC_SETUP" => env!("LC_SETUP"),
        _ => "",
    }
}

fn run(args: &[String]) -> Result<String, String> {
    run_bin(env!("LC_SETUP"), args)
}

fn run_test(args: &[String]) -> Result<String, String> {
    run_bin(env!("LC_SETUP_TEST"), args)
}

fn run_bin(bin: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("cannot start the confinement launcher: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let mut detail = stdout.trim().to_string();
        if !stderr.trim().is_empty() {
            if !detail.is_empty() {
                detail.push('\n');
            }
            detail.push_str(stderr.trim());
        }
        if detail.is_empty() {
            detail = format!("the launcher exited {:?}", output.status);
        }
        return Err(detail);
    }
    if stdout.trim().is_empty() {
        return Err(format!("the launcher wrote nothing\n{stderr}"));
    }
    Ok(stdout)
}

pub fn parse_report(raw: &str) -> Result<Report, String> {
    let mut enforced = None;
    let mut ops = Vec::new();
    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("enforced ") {
            enforced = Some(parse_enforced(rest)?);
        } else if line.starts_with("op=") {
            ops.push(parse_op(line)?);
        } else {
            return Err(format!("unexpected launcher line: {line}"));
        }
    }
    let enforced = enforced.ok_or("the launcher did not report enforcement")?;
    Ok(Report {
        enforced,
        ops,
        raw: raw.to_string(),
    })
}

fn parse_enforced(rest: &str) -> Result<Enforced, String> {
    let mut abi = None;
    let mut uid = None;
    let mut caps = None;
    let mut nnp = None;
    let mut netns = None;
    let mut storage_rights = None;
    for field in rest.split_whitespace() {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| format!("bad enforcement field: {field}"))?;
        match key {
            "abi" => abi = Some(parse_i32(value)?),
            "uid" => uid = Some(parse_i32(value)?),
            "caps" => caps = Some(value.to_string()),
            "nnp" => nnp = Some(parse_i32(value)?),
            "netns" => netns = Some(value.to_string()),
            "storage_rights" => storage_rights = Some(parse_u64_hex(value)?),
            _ => return Err(format!("unknown enforcement field: {key}")),
        }
    }
    Ok(Enforced {
        abi: abi.ok_or("enforcement omitted abi")?,
        uid: uid.ok_or("enforcement omitted uid")?,
        caps: caps.ok_or("enforcement omitted caps")?.to_string(),
        nnp: nnp.ok_or("enforcement omitted nnp")?,
        netns: netns.ok_or("enforcement omitted netns")?.to_string(),
        storage_rights: storage_rights.ok_or("enforcement omitted storage_rights")?,
    })
}

fn parse_u64_hex(text: &str) -> Result<u64, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|_| format!("not a hex mask: {text}"))
}

fn parse_op(line: &str) -> Result<Op, String> {
    let rest = line
        .strip_prefix("op=")
        .ok_or_else(|| format!("bad op line: {line}"))?;
    let (op, rest) = rest
        .split_once(" result=")
        .ok_or_else(|| format!("op line has no result: {line}"))?;
    let (result, errno, reason) = if let Some((result, rest)) = rest.split_once(" errno=") {
        let (errno, reason) = rest
            .split_once(" reason=")
            .ok_or_else(|| format!("op line has no reason: {line}"))?;
        (result, Some(parse_i32(errno)?), reason)
    } else {
        let (result, reason) = rest
            .split_once(" reason=")
            .ok_or_else(|| format!("op line has no reason: {line}"))?;
        (result, None, reason)
    };
    if reason.is_empty() {
        return Err(format!("op line has an empty reason: {line}"));
    }
    Ok(Op {
        op: op.to_string(),
        result: result.to_string(),
        errno,
        reason: reason.to_string(),
    })
}

fn parse_i32(text: &str) -> Result<i32, String> {
    text.parse::<i32>()
        .map_err(|_| format!("not an integer: {text}"))
}

/// Op lines only. Used for an unconfined positive control that has no
/// `enforced` line.
pub fn parse_ops(raw: &str) -> Result<Vec<Op>, String> {
    let mut ops = Vec::new();
    for line in raw.lines() {
        if line.is_empty() || line.starts_with("enforced ") {
            continue;
        }
        if line.starts_with("op=") {
            ops.push(parse_op(line)?);
        } else if line.starts_with("bad args") {
            return Err(raw.to_string());
        } else {
            return Err(format!("unexpected probe line: {line}"));
        }
    }
    Ok(ops)
}

/// Run the freestanding probe with no launcher, so a denied confined row
/// has a matching unconfined success.
pub fn run_unconfined(launch: &Launch) -> Result<Vec<Op>, String> {
    let storage2 = launch
        .storage2
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "-".to_string());
    let output = Command::new(env_bin("LC_PROBE"))
        .args([
            "check",
            &launch.storage.display().to_string(),
            &launch.outside.display().to_string(),
            &launch.parent.display().to_string(),
            &launch.copy.display().to_string(),
            &storage2,
            "1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("cannot start the unconfined probe: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.trim().is_empty() {
        return Err(format!("the unconfined probe wrote nothing\n{stderr}"));
    }
    parse_ops(&stdout).map_err(|err| format!("{err}\n{stdout}"))
}

pub fn op<'a>(report: &'a Report, name: &str) -> Result<&'a Op, String> {
    report
        .ops
        .iter()
        .find(|op| op.op == name)
        .ok_or_else(|| format!("missing {name}\n{}", report.raw))
}

/// The profile's declared allows, read from a file the macOS lane already
/// wrote. This crate does not modify that file.
pub fn read_profile(path: &Path) -> Result<Profile, String> {
    let text =
        fs::read_to_string(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    parse_profile(&text)
}

/// One extra Landlock path for a dynamically linked provider.
#[derive(Debug, Clone)]
pub struct ExtraPath {
    pub path: PathBuf,
    /// Read and execute. A loader file is read-only.
    pub execute: bool,
}

/// A shipping provider binary under the same confinement as the probe.
#[derive(Debug, Clone)]
pub struct ProviderLaunch {
    pub deny_network: bool,
    /// The file `execve` is asked to start.
    pub binary: PathBuf,
    /// The one file Landlock allows to execute as the program. An unbound
    /// copy sets `binary` to the copy and `execute` to the real program.
    pub execute: PathBuf,
    pub storage_root: PathBuf,
    pub parent: PathBuf,
    pub copy: PathBuf,
    /// Read the parent directory after a private mount that contains only
    /// `storage_root`. Wallet init syncs that parent.
    pub read_parent: bool,
    /// Load the lab witness into the provider process.
    pub preload: bool,
    /// Path the witness opens to record a Landlock outside-read errno.
    pub outside: Option<PathBuf>,
    pub paths: Vec<ExtraPath>,
}

pub struct RunningProvider {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: Arc<Mutex<String>>,
    pub enforced: Enforced,
}

impl RunningProvider {
    pub fn request(&mut self, line: &str) -> Result<String, String> {
        writeln!(self.stdin, "{line}")
            .map_err(|err| format!("writing the request failed: {err}"))?;
        self.stdin
            .flush()
            .map_err(|err| format!("writing the request failed: {err}"))?;
        let mut response = String::new();
        let n = self
            .stdout
            .read_line(&mut response)
            .map_err(|err| format!("reading the response failed: {err}; {}", self.stderr()))?;
        if n == 0 {
            return Err(format!("the provider closed stdout; {}", self.stderr()));
        }
        Ok(response)
    }

    pub fn stderr(&self) -> String {
        self.stderr.lock().expect("stderr lock").clone()
    }

    pub fn launcher_pid(&self) -> u32 {
        self.child.id()
    }

    pub fn wait(mut self) -> Result<std::process::ExitStatus, String> {
        self.child
            .wait()
            .map_err(|err| format!("waiting for the provider failed: {err}"))
    }
}

impl Drop for RunningProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn_provider(launch: &ProviderLaunch) -> Result<RunningProvider, String> {
    let policy = write_provider_policy(launch)?;
    let mut child = Command::new(env!("LC_SETUP"))
        .arg(policy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("cannot start the confinement launcher: {err}"))?;
    let stdin = child.stdin.take().ok_or("the launcher has no stdin")?;
    let stdout = child.stdout.take().ok_or("the launcher has no stdout")?;
    let stderr = child.stderr.take().ok_or("the launcher has no stderr")?;
    let stderr_text = Arc::new(Mutex::new(String::new()));
    let collected = Arc::clone(&stderr_text);
    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => collected.lock().expect("stderr lock").push_str(&line),
            }
        }
    });
    let started = Instant::now();
    let enforced = loop {
        let text = stderr_text.lock().expect("stderr lock").clone();
        if let Some(line) = text.lines().find(|line| line.starts_with("enforced ")) {
            break parse_enforced(line.strip_prefix("enforced ").unwrap())?;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("the launcher status failed: {err}"))?
        {
            return Err(format!(
                "the provider did not start ({status}); {}",
                stderr_text.lock().expect("stderr lock")
            ));
        }
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            return Err(format!(
                "the provider did not report enforcement; {}",
                stderr_text.lock().expect("stderr lock")
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(RunningProvider {
        child,
        stdin,
        stdout: BufReader::new(stdout),
        stderr: stderr_text,
        enforced,
    })
}

/// Host pid and `CapBnd` hex from the confined process status file.
///
/// The launcher forks a waiter, and that waiter forks the process that
/// becomes pid 1 and execs the provider. `/proc/<pid>/status` is the file
/// that process calls `/proc/self/status`. Landlock does not grant `/proc`,
/// so the host reads the node while the provider is alive.
pub fn confined_cap_bnd(launcher_pid: u32) -> Result<(u32, String), String> {
    let waiter = only_child(launcher_pid)?;
    let confined = only_child(waiter)?;
    let status = fs::read_to_string(format!("/proc/{confined}/status"))
        .map_err(|err| format!("cannot read /proc/{confined}/status: {err}"))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("CapBnd:"))
        .ok_or_else(|| format!("/proc/{confined}/status has no CapBnd"))?;
    let hex = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("CapBnd line has no value: {line}"))?;
    if hex.chars().any(|ch| !ch.is_ascii_hexdigit()) {
        return Err(format!("CapBnd is not hex: {hex}"));
    }
    Ok((confined, hex.to_string()))
}

fn only_child(pid: u32) -> Result<u32, String> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let started = Instant::now();
    loop {
        let text = fs::read_to_string(&path).map_err(|err| format!("cannot read {path}: {err}"))?;
        let kids: Vec<u32> = text
            .split_whitespace()
            .filter_map(|item| item.parse().ok())
            .collect();
        if kids.len() == 1 {
            return Ok(kids[0]);
        }
        if started.elapsed() > Duration::from_secs(2) {
            return Err(format!(
                "{path} listed {kids:?}, expected one confined child"
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn write_provider_policy(launch: &ProviderLaunch) -> Result<PathBuf, String> {
    let parent = launch
        .storage_root
        .parent()
        .ok_or("the storage root has no parent")?;
    let path = parent.join("launch.policy");
    let outside = launch
        .outside
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut body = format!(
        "mode=provider\ndeny_network={}\nhelper={}\nexecute={}\nstorage_root={}\nstorage=-\nstorage2=-\noutside={}\nparent={}\ncopy={}\nread_parent={}\n",
        if launch.deny_network { "1" } else { "0" },
        launch.binary.display(),
        launch.execute.display(),
        launch.storage_root.display(),
        outside,
        launch.parent.display(),
        launch.copy.display(),
        if launch.read_parent { "1" } else { "0" },
    );
    for extra in &launch.paths {
        let key = if extra.execute {
            "read_exec"
        } else {
            "read_only"
        };
        body.push_str(&format!("{key}={}\n", extra.path.display()));
    }
    if launch.preload {
        body.push_str(&format!(
            "preload={}\nread_exec={}\n",
            env!("LC_WITNESS"),
            env!("LC_WITNESS")
        ));
    }
    fs::write(&path, body).map_err(|err| format!("cannot write policy: {err}"))?;
    Ok(path)
}
