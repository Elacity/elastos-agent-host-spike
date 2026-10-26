//! The lane's one owner of throwaway Homes and bounded Runtime launches.

use std::cell::Cell;
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, &'static str>;
static SERIAL: AtomicU64 = AtomicU64::new(0);

/// Match sources.rs:default_data_dir on the only supported test host.
pub fn data_dir(home: &Path) -> Result<PathBuf> {
    if !cfg!(target_os = "macos") {
        return Err("throwaway Homes require macOS");
    }
    Ok(home.join("Library/Application Support/elastos"))
}

fn target() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target")
}

fn inside(path: &Path, root: &Path) -> bool {
    path != root
        && path.starts_with(root)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

// Examine each in-root component before going further. In particular, never
// canonicalize an outside path or follow a symlink to learn where it leads.
fn directories_only(path: &Path, root: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut cursor = root.to_path_buf();
    for part in relative.components() {
        cursor.push(part);
        match fs::symlink_metadata(&cursor) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            _ => return false,
        }
    }
    true
}

fn same_directory(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev() && first.ino() == second.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (first, second);
        false
    }
}

/// Call `finish` only after all test assertions pass. Every other drop keeps
/// the root and reports its path, including a constructor or launch refusal.
#[derive(Debug)]
pub struct ThrowawayHome {
    root: PathBuf,
    identity: Metadata,
    home: PathBuf,
    data: PathBuf,
    temp: PathBuf,
    removed: bool,
    keep: Cell<bool>,
}

impl ThrowawayHome {
    pub fn new() -> Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "could not name a fresh throwaway root")?
            .as_nanos();
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        Self::create_at(&target().join(format!("home-{}-{stamp}-{serial}", std::process::id())))
    }

    /// Also exposes the collision case to tests. Only direct children of the
    /// lane's target directory are eligible; existing paths are always refused.
    pub fn create_at(root: &Path) -> Result<Self> {
        // Check platform support before creating anything.
        data_dir(root)?;
        let target = target();
        if root.parent() != Some(target.as_path()) || !inside(root, &target) {
            return Err("throwaway root must be directly inside the lane target");
        }
        match fs::create_dir(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("could not create the lane target"),
        }
        if !directories_only(&target, Path::new(env!("CARGO_MANIFEST_DIR"))) {
            return Err("lane target must be a directory without symlinks");
        }
        fs::create_dir(root).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "throwaway root is not fresh"
            } else {
                "could not create the throwaway root"
            }
        })?;
        let identity =
            fs::symlink_metadata(root).map_err(|_| "could not inspect the fresh root")?;
        let mut owned = Self {
            root: root.to_path_buf(),
            identity,
            home: root.join("home"),
            data: PathBuf::new(),
            temp: root.join("tmp"),
            removed: false,
            keep: Cell::new(false),
        };
        match include_str!("../fixtures/home-source.txt").trim() {
            "throwaway" => {}
            "inherited" => {
                owned.home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .ok_or("inherited HOME is unavailable")?;
            }
            _ => return Err("unknown throwaway Home fixture setting"),
        }
        owned.data = data_dir(&owned.home)?;
        owned.guard(&owned.home, &owned.data)?;
        for directory in [&owned.home, &owned.data, &owned.temp] {
            fs::create_dir_all(directory).map_err(|_| "could not prepare throwaway directories")?;
        }
        Ok(owned)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    pub fn temp(&self) -> &Path {
        &self.temp
    }

    fn check_root(&self) -> Result<()> {
        if !directories_only(&self.root, Path::new(env!("CARGO_MANIFEST_DIR"))) {
            return Err("throwaway root is no longer the fresh directory");
        }
        let metadata = fs::symlink_metadata(&self.root)
            .map_err(|_| "throwaway root is no longer the fresh directory")?;
        if !same_directory(&self.identity, &metadata) {
            return Err("throwaway root is no longer the fresh directory");
        }
        Ok(())
    }

    pub fn guard(&self, home: &Path, data: &Path) -> Result<()> {
        // Reject lexical escapes before any filesystem inspection of inputs.
        if !inside(home, &self.root) {
            return Err("home is outside the fresh throwaway root");
        }
        if !inside(data, &self.root) {
            return Err("data directory is outside the fresh throwaway root");
        }
        self.check_root()?;
        if !directories_only(home, &self.root) {
            return Err("home must use directories without symlinks");
        }
        if !directories_only(data, &self.root) {
            return Err("data directory must use directories without symlinks");
        }
        if !directories_only(&self.temp, &self.root) {
            return Err("temp directory must use directories without symlinks");
        }
        if data_dir(home)? != data {
            return Err("data directory does not match the macOS Home rule");
        }
        Ok(())
    }

    /// The only spawn site, shared by bounded launches and managed operators.
    fn spawn(
        &self,
        program: &Path,
        args: &[&str],
        operator: Option<&ThrowawayHome>,
    ) -> Result<CapturedChild> {
        self.guard(&self.home, &self.data)?;
        if let Some(operator) = operator {
            operator.guard(operator.home(), operator.data())?;
        }
        // Files avoid pipe backpressure and inherited-pipe EOF hangs. They are
        // created exclusively inside the guarded root and retained on failure.
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let stdout = File::create_new(self.root.join(format!("stdout-{serial}")))
            .map_err(|_| "could not create child stdout capture")?;
        let stderr = File::create_new(self.root.join(format!("stderr-{serial}")))
            .map_err(|_| "could not create child stderr capture")?;
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(&self.home)
            .env_clear()
            .env("HOME", &self.home)
            .env("TMPDIR", &self.temp)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("ELASTOS_CARRIER_MDNS", "0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(
                stdout
                    .try_clone()
                    .map_err(|_| "could not attach child stdout")?,
            )
            .stderr(
                stderr
                    .try_clone()
                    .map_err(|_| "could not attach child stderr")?,
            );
        if let Some(operator) = operator {
            // The client reads fixture coordinates from a guarded, borrowed Home.
            command.env(
                "ELASTOS_RUNTIME_COORDS_FILE",
                operator.data().join("runtime-coords.json"),
            );
        }
        let child = command
            .spawn()
            .map_err(|_| "could not start child process")?;
        Ok(CapturedChild {
            child,
            stdout,
            stderr,
        })
    }

    pub fn launch(&self, program: &Path, args: &[&str], bound: Duration) -> Result<Output> {
        let started = Instant::now();
        let mut spawned = self.spawn(program, args, None)?;
        let child = &mut spawned.child;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("could not wait for child process");
                }
            }
            if started.elapsed() >= bound {
                child
                    .kill()
                    .map_err(|_| "could not stop child past its time bound")?;
                child
                    .wait()
                    .map_err(|_| "could not reap child past its time bound")?;
                return Err("child exceeded its time bound");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Ok(Output {
            status,
            stdout: capture(&mut spawned.stdout)?,
            stderr: capture(&mut spawned.stderr)?,
        })
    }

    pub fn start(&self, program: &Path, args: &[&str]) -> Result<RunningChild<'_>> {
        Ok(RunningChild {
            home: self,
            spawned: self.spawn(program, args, None)?,
            stopped: false,
        })
    }

    pub fn group_is_alive(&self, pgid: u32) -> Result<bool> {
        let output = self.launch(
            Path::new("/usr/bin/pgrep"),
            &["-g", &pgid.to_string()],
            Duration::from_secs(1),
        )?;
        if !output.stderr.is_empty() {
            return Err("could not inspect child process group");
        }
        match output.status.code() {
            Some(1) if output.stdout.is_empty() => Ok(false),
            Some(0) => {
                let text = std::str::from_utf8(&output.stdout)
                    .map_err(|_| "process group listing is not UTF-8")?;
                if text.lines().next().is_none()
                    || !text
                        .lines()
                        .all(|line| line.parse::<u32>().is_ok_and(|pid| pid > 0))
                {
                    return Err("process group listing is empty or unparseable");
                }
                Ok(true)
            }
            _ => Err("could not inspect child process group"),
        }
    }

    pub fn finish(mut self) -> Result<()> {
        if self.keep.get() {
            return Err("keep the root after an unstopped child or failed stop");
        }
        self.check_root()?;
        fs::remove_dir_all(&self.root).map_err(|_| "could not remove the passed test root")?;
        self.removed = true;
        Ok(())
    }
}

struct CapturedChild {
    child: Child,
    stdout: File,
    stderr: File,
}

/// Borrows the Home so its root cannot be removed while the child is owned.
/// Captures stay in the guarded root for fixture acceptance checks.
pub struct RunningChild<'a> {
    home: &'a ThrowawayHome,
    spawned: CapturedChild,
    stopped: bool,
}

impl RunningChild<'_> {
    pub fn pgid(&self) -> u32 {
        self.spawned.child.id()
    }

    pub fn is_alive(&mut self) -> Result<bool> {
        self.spawned
            .child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|_| "could not inspect managed child")
    }

    /// Observe exit without signalling the child. Preserve its OS status so
    /// callers can reject signal exits. A surviving descendant fails cleanup.
    fn try_output(&mut self) -> Result<Option<Output>> {
        let Some(status) = self
            .spawned
            .child
            .try_wait()
            .map_err(|_| "could not collect managed child status")?
        else {
            return Ok(None);
        };
        if self.home.group_is_alive(self.pgid())? {
            return Err("completed child left a live process group");
        }
        let output = Output {
            status,
            stdout: capture(&mut self.spawned.stdout)?,
            stderr: capture(&mut self.spawned.stderr)?,
        };
        self.stopped = true;
        Ok(Some(output))
    }

    fn signal(&self, signal: &str, group: bool) -> Result<()> {
        let target = if group {
            format!("-{}", self.pgid())
        } else {
            self.pgid().to_string()
        };
        let output = self.home.launch(
            Path::new("/bin/kill"),
            &[signal, &target],
            Duration::from_secs(1),
        )?;
        if !output.status.success() {
            return Err("could not signal managed child or its group");
        }
        Ok(())
    }

    fn kill_group(&mut self) -> Result<()> {
        // Signal first even if the leader exited: its children can still live.
        let _ = self.signal("-KILL", true);
        let bound = Instant::now();
        while bound.elapsed() < Duration::from_secs(2) {
            if !self.is_alive()? && !self.home.group_is_alive(self.pgid())? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err("managed process group remains after SIGKILL")
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let result = self.stop_within_bound();
        if result.is_err() {
            self.home.keep.set(true);
            self.kill_group()?;
        }
        self.stopped = true;
        result
    }

    fn stop_within_bound(&mut self) -> Result<()> {
        let started = Instant::now();
        if self.is_alive()? {
            self.signal("-TERM", false)?;
        }
        while started.elapsed() < Duration::from_secs(10) {
            if !self.is_alive()? && !self.home.group_is_alive(self.pgid())? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err("managed child or its group exceeded the 10 second stop bound")
    }
}

/// Start every client before collecting any result, through the same spawn
/// site as launch/start. Borrow the operator until all clients have settled.
pub struct Launch<'a> {
    pub home: &'a ThrowawayHome,
    pub program: &'a Path,
    pub args: Vec<&'a str>,
}

pub struct RunningInstances<'a> {
    children: Vec<RunningChild<'a>>,
    started: Instant,
}

pub struct Completion {
    pub output: Output,
    /// Includes all launches, polling, capture and group-drain checks.
    pub elapsed: Duration,
}

impl<'a> RunningInstances<'a> {
    pub fn start(launches: &[Launch<'a>], operator: Option<&'a ThrowawayHome>) -> Result<Self> {
        let mut group = Self {
            children: Vec::new(),
            started: Instant::now(),
        };
        for launch in launches {
            group.children.push(RunningChild {
                home: launch.home,
                spawned: launch.home.spawn(launch.program, &launch.args, operator)?,
                stopped: false,
            });
        }
        Ok(group)
    }

    /// One deadline from before the first spawn. Poll all children so a slow
    /// member cannot hide a sibling's result. Drop kills any unfinished groups.
    pub fn collect(self, bound: Duration) -> Result<Vec<Completion>> {
        self.collect_with(bound, || Ok(()))
    }

    /// Service fixture approvals while the existing children wait. A controller
    /// error uses the same group cleanup as any other collection failure.
    pub fn collect_with(
        mut self,
        bound: Duration,
        mut service: impl FnMut() -> Result<()>,
    ) -> Result<Vec<Completion>> {
        let mut results: Vec<_> = self.children.iter().map(|_| None).collect();
        while results.iter().any(Option::is_none) {
            service()?;
            for (child, result) in self.children.iter_mut().zip(&mut results) {
                if result.is_none() {
                    if let Some(output) = child.try_output()? {
                        *result = Some(Completion {
                            output,
                            elapsed: self.started.elapsed(),
                        });
                    }
                }
            }
            if self.started.elapsed() >= bound {
                return Err("instances exceeded their shared time bound; harness cleanup is not a Runtime stop");
            }
            if results.iter().any(Option::is_none) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(results.into_iter().map(Option::unwrap).collect())
    }
}

impl Drop for RunningChild<'_> {
    fn drop(&mut self) {
        if !self.stopped {
            self.home.keep.set(true);
            if let Err(reason) = self.kill_group() {
                eprintln!("managed child cleanup failed: {reason}");
            }
        }
    }
}

fn capture(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "could not rewind child capture")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "could not read child capture")?;
    Ok(bytes)
}

impl Drop for ThrowawayHome {
    fn drop(&mut self) {
        if !self.removed {
            if let Ok(relative) = self.root.strip_prefix(env!("CARGO_MANIFEST_DIR")) {
                eprintln!(
                    "retained throwaway root: lab/agent-conformance/{}",
                    relative.display()
                );
            }
        }
    }
}
