//! The lane's one harness. It builds this checkout's Runtime and
//! localhost-provider, builds components with the repository's
//! `scripts/build-component-capsule.sh`, and launches them in a throwaway Home
//! through `elastos serve` (the operator) and `elastos run`. This is the
//! Runtime path the agent-conformance lane uses; its data-dir rule covers
//! Linux as well as macOS.

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `ALLOWED_BUS_IMPORTS` in `elastos/crates/elastos-server/src/component.rs`.
pub const RUNTIME_ALLOWLIST: [&str; 5] = [
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

const OPERATOR_CONFIG: &[u8] = include_bytes!("../fixtures/operator-config.toml");

static SERIAL: AtomicU64 = AtomicU64::new(0);
static BUILD: Mutex<()> = Mutex::new(());

pub fn lane() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn repository() -> PathBuf {
    lane()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Raw-byte search used to prove a sentence is absent from guest bytes.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

fn fresh(prefix: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{stamp}-{serial}", std::process::id())
}

/// Offline, locked builds with every output under this lane's `target/`.
fn offline(program: &str, target: &Path) -> Command {
    fs::create_dir_all(target.join("tmp")).expect("create the lane build directory");
    let mut command = Command::new(program);
    command
        .current_dir(repository())
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
        .env("TMPDIR", target.join("tmp"))
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    command
}

pub struct Binary {
    pub path: PathBuf,
    pub sha256: String,
}

pub fn runtime() -> &'static Binary {
    static CELL: OnceLock<Result<Binary, String>> = OnceLock::new();
    native(&CELL, "elastos-server", "elastos")
}

pub fn provider() -> &'static Binary {
    static CELL: OnceLock<Result<Binary, String>> = OnceLock::new();
    native(&CELL, "localhost-provider", "localhost-provider")
}

fn native(
    cell: &'static OnceLock<Result<Binary, String>>,
    package: &str,
    name: &str,
) -> &'static Binary {
    cell.get_or_init(|| {
        let _serial = BUILD.lock().unwrap_or_else(|error| error.into_inner());
        let target = lane().join("target/runtime");
        let output = offline("cargo", &target)
            .args(["build", "--locked", "--offline", "--manifest-path"])
            .args(["elastos/Cargo.toml", "-p", package, "--bin", name])
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .output()
            .map_err(|error| format!("start the {name} build: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "{name} build failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let path = target.join("debug").join(name);
        let bytes = fs::read(&path).map_err(|error| format!("read {name}: {error}"))?;
        Ok(Binary {
            path,
            sha256: sha256(&bytes),
        })
    })
    .as_ref()
    .unwrap_or_else(|reason| panic!("{reason}"))
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub manifest: Vec<u8>,
}

/// One exact text replacement in a copied build input. The anchor must occur
/// exactly once.
pub struct Edit<'a> {
    pub file: &'a str,
    pub old: &'a str,
    pub new: &'a str,
}

/// Copy a capsule's listed inputs to a fresh tree under this lane's target, at
/// the same repository-relative place, beside a copy of the one bus WIT file,
/// so the capsule's relative WIT path resolves unchanged. Edits change only
/// the copy. The repository script builds it; the copy is removed afterwards.
pub fn build_component(
    source: &str,
    inputs: &[&str],
    variant: &str,
    rustflags: &str,
    edits: &[Edit],
) -> Built {
    let _serial = BUILD.lock().unwrap_or_else(|error| error.into_inner());
    let tree = lane().join("target/build-inputs").join(fresh(variant));
    copy(
        &repository().join("elastos/wit/elastos-bus-v1.wit"),
        &tree.join("elastos/wit/elastos-bus-v1.wit"),
    );
    let capsule = tree.join(source);
    for input in inputs {
        copy(&repository().join(source).join(input), &capsule.join(input));
    }
    for edit in edits {
        let path = capsule.join(edit.file);
        let text = fs::read_to_string(&path).expect("read the copied input");
        assert_eq!(
            text.matches(edit.old).count(),
            1,
            "edit anchor must occur exactly once in {}",
            edit.file
        );
        fs::write(&path, text.replacen(edit.old, edit.new, 1)).expect("edit the copy");
    }
    let output = offline("bash", &lane().join("target/components").join(variant))
        .arg(repository().join("scripts/build-component-capsule.sh"))
        .arg(&capsule)
        .env("RUSTFLAGS", rustflags)
        .output()
        .expect("start the component build");
    assert!(
        output.status.success(),
        "{variant} component build failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = fs::read(capsule.join("capsule.json")).expect("read the copied manifest");
    let bytes = fs::read(capsule.join(entrypoint(&manifest))).expect("read the built component");
    fs::remove_dir_all(&tree).expect("remove the build copy");
    Built { bytes, manifest }
}

fn copy(source: &Path, destination: &Path) {
    let metadata = fs::symlink_metadata(source).expect("inspect a build input");
    assert!(
        !metadata.file_type().is_symlink(),
        "build input is a symlink: {}",
        source.display()
    );
    if metadata.is_dir() {
        fs::create_dir_all(destination).expect("create a copied directory");
        for entry in fs::read_dir(source).expect("list a build input") {
            let entry = entry.expect("read a build input entry");
            copy(&entry.path(), &destination.join(entry.file_name()));
        }
    } else {
        fs::create_dir_all(destination.parent().unwrap()).expect("create a copy parent");
        fs::copy(source, destination).expect("copy a build input");
    }
}

fn entrypoint(manifest: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(manifest).expect("manifest is JSON");
    value["entrypoint"]
        .as_str()
        .expect("manifest names an entrypoint")
        .to_owned()
}

/// The root component's import names, read independently of the Runtime.
/// Names that wit-component generates for types and functions are left out,
/// as the Runtime's own check skips them.
pub fn component_imports(bytes: &[u8]) -> Vec<String> {
    use wasmparser::{Parser, Payload};
    let mut names = Vec::new();
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("parse the component") {
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(section) if depth == 0 => {
                for import in section {
                    let name = import.expect("read a component import").name.0;
                    if !name.starts_with("import-type-") && name != "import-func-run" {
                        names.push(name.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    names
}

/// `dirs::data_dir()` joined with `elastos`, for a cleared environment.
pub fn data_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/elastos")
    } else {
        home.join(".local/share/elastos")
    }
}

fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        (os, arch) => panic!("no components.json platform for {os}/{arch}"),
    }
}

pub struct Run {
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn exited_ok(&self) -> bool {
        self.status.is_some_and(|status| status.success())
    }

    pub fn has_line(&self, line: &str) -> bool {
        self.stderr.lines().any(|candidate| candidate == line)
    }

    pub fn line_with(&self, needle: &str) -> Option<&str> {
        self.stderr.lines().find(|line| line.contains(needle))
    }
}

/// A fresh root under this lane's target with its own HOME, data dir and
/// TMPDIR. `finish` removes it after a pass; a failed test keeps it.
pub struct Home {
    root: PathBuf,
    home: PathBuf,
    data: PathBuf,
    temp: PathBuf,
    finished: bool,
}

struct Spawned {
    child: Child,
    stdout: File,
    stderr: File,
}

impl Home {
    pub fn new() -> Self {
        let parent = lane().join("target/homes");
        fs::create_dir_all(&parent).expect("create the homes directory");
        let root = parent.join(fresh("home"));
        fs::create_dir(&root).expect("create a fresh throwaway root");
        let home = root.join("home");
        let data = data_dir(&home);
        let temp = root.join("tmp");
        for directory in [&home, &data, &temp] {
            fs::create_dir_all(directory).expect("create throwaway directories");
        }
        Self {
            root,
            home,
            data,
            temp,
            finished: false,
        }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    pub fn stage(&self, name: &str, bytes: &[u8], manifest: &[u8]) -> PathBuf {
        let directory = self.root.join("capsules").join(name);
        fs::create_dir_all(&directory).expect("create the capsule directory");
        File::create_new(directory.join("capsule.json"))
            .and_then(|mut file| file.write_all(manifest))
            .expect("stage the manifest");
        File::create_new(directory.join(entrypoint(manifest)))
            .and_then(|mut file| file.write_all(bytes))
            .expect("stage the component");
        directory
    }

    /// Exclusive creation inside this home only.
    pub fn seed(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).expect("create the fixture directory");
        File::create_new(&path)
            .and_then(|mut file| file.write_all(bytes))
            .expect("seed the fixture file");
        path
    }

    /// Every stdout and stderr capture of every child in this home.
    pub fn captures(&self) -> Vec<Vec<u8>> {
        let mut captures = Vec::new();
        for entry in fs::read_dir(&self.root).expect("list the throwaway root") {
            let entry = entry.expect("read a root entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("stdout-") || name.starts_with("stderr-") {
                captures.push(fs::read(entry.path()).expect("read a capture"));
            }
        }
        captures
    }

    fn spawn(&self, program: &Path, args: &[&str]) -> Spawned {
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let stdout = File::create_new(self.root.join(format!("stdout-{serial}")))
            .expect("create the stdout capture");
        let stderr = File::create_new(self.root.join(format!("stderr-{serial}")))
            .expect("create the stderr capture");
        let child = Command::new(program)
            .args(args)
            .current_dir(&self.home)
            .env_clear()
            .env("HOME", &self.home)
            .env("TMPDIR", &self.temp)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("ELASTOS_CARRIER_MDNS", "0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone().expect("attach stdout"))
            .stderr(stderr.try_clone().expect("attach stderr"))
            .spawn()
            .expect("start the child");
        Spawned {
            child,
            stdout,
            stderr,
        }
    }

    /// `elastos run <capsule>` against this home's operator, within `bound`.
    pub fn run(&self, capsule: &Path, bound: Duration) -> Run {
        let mut spawned = self.spawn(&runtime().path, &["run", capsule.to_str().unwrap()]);
        let started = Instant::now();
        let status = loop {
            if let Some(status) = spawned.child.try_wait().expect("wait for elastos run") {
                break Some(status);
            }
            if started.elapsed() >= bound {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stop_group(spawned.child.id());
        if status.is_none() {
            let _ = spawned.child.wait();
        }
        Run {
            status,
            stdout: read_capture(&mut spawned.stdout),
            stderr: read_capture(&mut spawned.stderr),
        }
    }

    pub fn finish(mut self) {
        fs::remove_dir_all(&self.root).expect("remove the passed throwaway root");
        self.finished = true;
    }
}

impl Default for Home {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(relative) = self.root.strip_prefix(repository()) {
                eprintln!("retained throwaway root: {}", relative.display());
            }
        }
    }
}

fn read_capture(file: &mut File) -> String {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0)).expect("rewind a capture");
    file.read_to_string(&mut text)
        .expect("captures are UTF-8 text");
    text
}

fn group_alive(pgid: u32) -> bool {
    Command::new("/usr/bin/pgrep")
        .args(["-g", &pgid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn signal_group(pgid: u32, signal: &str) {
    let _ = Command::new("/bin/kill")
        .args(["-s", signal, "--", &format!("-{pgid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// TERM the group, then KILL whatever remains after ten seconds.
fn stop_group(pgid: u32) {
    if !group_alive(pgid) {
        return;
    }
    signal_group(pgid, "TERM");
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if !group_alive(pgid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal_group(pgid, "KILL");
}

/// `elastos serve` on a loopback port, with the checkout's localhost-provider
/// installed and pinned by checksum in `components.json`.
pub struct Operator<'a> {
    home: &'a Home,
    child: Child,
    stopped: bool,
}

impl<'a> Operator<'a> {
    pub fn start(home: &'a Home) -> Self {
        install_provider(home);
        File::create_new(home.data.join("config.toml"))
            .and_then(|mut file| file.write_all(OPERATOR_CONFIG))
            .expect("write the operator config");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("pick a loopback port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let storage = home.root.join("storage");
        let spawned = home.spawn(
            &runtime().path,
            &[
                "serve",
                "--addr",
                &format!("127.0.0.1:{port}"),
                "--storage-path",
                storage.to_str().unwrap(),
            ],
        );
        let mut operator = Self {
            home,
            child: spawned.child,
            stopped: false,
        };
        let started = Instant::now();
        loop {
            assert!(
                operator.child.try_wait().unwrap().is_none(),
                "operator exited before it was ready"
            );
            if home.data.join("runtime-coords.json").exists() && health_is_ok(port) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "operator was not ready within 60 seconds"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        operator
    }

    pub fn stop(mut self) {
        stop_group(self.child.id());
        let _ = self.child.wait();
        self.stopped = true;
    }
}

impl Drop for Operator<'_> {
    fn drop(&mut self) {
        if !self.stopped {
            stop_group(self.child.id());
            let _ = self.child.wait();
            eprintln!(
                "operator stopped during a failure; captures kept under {}",
                self.home.root.display()
            );
        }
    }
}

fn install_provider(home: &Home) {
    let provider = provider();
    let bytes = fs::read(&provider.path).expect("read the provider binary");
    fs::create_dir_all(home.data.join("bin")).expect("create the data bin directory");
    let installed = home.data.join("bin/localhost-provider");
    let mut file = File::create_new(&installed).expect("install the provider");
    file.write_all(&bytes).expect("write the provider");
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .expect("make the provider executable");
    }
    let source: serde_json::Value = serde_json::from_slice(
        &fs::read(repository().join("components.json")).expect("read components.json"),
    )
    .expect("components.json is JSON");
    let mut entry = source["external"]["localhost-provider"].clone();
    entry["platforms"][platform()] = serde_json::json!({
        "checksum": format!("sha256:{}", provider.sha256),
        "size": bytes.len(),
        "install_path": "bin/localhost-provider",
    });
    let manifest = serde_json::json!({
        "external": {"localhost-provider": entry},
        "profiles": {},
    });
    File::create_new(home.data.join("components.json"))
        .and_then(|file| Ok(serde_json::to_writer_pretty(file, &manifest)?))
        .expect("write components.json");
}

fn health_is_ok(port: u16) -> bool {
    let bound = Duration::from_millis(200);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, bound) else {
        return false;
    };
    if stream.set_read_timeout(Some(bound)).is_err()
        || stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = [0; 16];
    matches!(stream.read(&mut response), Ok(len) if response[..len].starts_with(b"HTTP/1.1 200 "))
}
