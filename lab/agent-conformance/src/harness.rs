//! The lane's one owner of throwaway Homes and bounded Runtime launches.

use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
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

    /// All Runtime process starts belong here. Future operator support extends
    /// this primitive and its environment test instead of adding another spawn.
    pub fn launch(&self, program: &Path, args: &[&str], bound: Duration) -> Result<Output> {
        self.guard(&self.home, &self.data)?;
        // Files avoid pipe backpressure and inherited-pipe EOF hangs. They are
        // created exclusively inside the guarded root and retained on failure.
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let mut stdout = File::create_new(self.root.join(format!("stdout-{serial}")))
            .map_err(|_| "could not create child stdout capture")?;
        let mut stderr = File::create_new(self.root.join(format!("stderr-{serial}")))
            .map_err(|_| "could not create child stderr capture")?;
        let started = Instant::now();
        let mut child = Command::new(program)
            .args(args)
            .current_dir(&self.home)
            .env_clear()
            .env("HOME", &self.home)
            .env("TMPDIR", &self.temp)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
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
            )
            .spawn()
            .map_err(|_| "could not start child process")?;
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
            stdout: capture(&mut stdout)?,
            stderr: capture(&mut stderr)?,
        })
    }

    pub fn finish(mut self) -> Result<()> {
        self.check_root()?;
        fs::remove_dir_all(&self.root).map_err(|_| "could not remove the passed test root")?;
        self.removed = true;
        Ok(())
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
