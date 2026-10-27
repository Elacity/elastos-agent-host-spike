//! The lane's one harness. It builds this checkout's Runtime and
//! localhost-provider, builds components with the repository's
//! `scripts/build-component-capsule.sh`, and launches them in a throwaway Home
//! through `elastos serve` (the operator) and `elastos run`. This is the
//! Runtime path the agent-conformance lane uses; its data-dir rule covers
//! Linux as well as macOS.

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
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

/// Bytes the Runtime `load` path will open from this staged capsule.
pub fn staged_component_bytes(capsule: &Path, manifest: &[u8]) -> Vec<u8> {
    fs::read(capsule.join(entrypoint(manifest))).expect("read the staged component")
}

/// Hash of the exact bytes that will be executed. The staged file and the
/// in-memory copy that the test hashed must match. A TOCTOU swap FAILs.
pub fn executed_bytes_hash(staged: &[u8], claimed: &[u8]) -> Result<String, String> {
    let staged_hash = sha256(staged);
    let claimed_hash = sha256(claimed);
    if staged_hash != claimed_hash {
        return Err(format!(
            "module_hash must be of the exact bytes executed (staged {staged_hash}, hashed {claimed_hash})"
        ));
    }
    Ok(staged_hash)
}

/// Host-held seal of a staged component, hashed from one opened fd.
#[derive(Clone, Debug)]
pub struct StagedSeal {
    pub path: PathBuf,
    pub inode: u64,
    pub size: u64,
    pub hash: String,
}

/// Open the staged path, refuse a symlink, and hash the bytes from that
/// same fd. A later rename-swap changes the inode or hash.
pub fn seal_staged_bytes(path: &Path) -> Result<StagedSeal, String> {
    let link = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if link.file_type().is_symlink() {
        return Err("staged component must not be a symlink".into());
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if meta.ino() != link.ino() || meta.len() != link.len() {
        return Err("module_hash must be of the exact bytes executed".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != meta.len() {
        return Err("module_hash must be of the exact bytes executed".into());
    }
    Ok(StagedSeal {
        path: path.to_path_buf(),
        inode: meta.ino(),
        size: meta.len(),
        hash: sha256(&bytes),
    })
}

/// Re-open the staged path after load and refuse if the inode, size, or
/// hash moved. Closes the rename-swap window between hash and load.
pub fn executed_bytes_still_sealed(seal: &StagedSeal) -> Result<String, String> {
    let again = seal_staged_bytes(&seal.path)?;
    if again.inode != seal.inode || again.size != seal.size || again.hash != seal.hash {
        return Err("module_hash must be of the exact bytes executed".into());
    }
    Ok(seal.hash.clone())
}

/// Seal the staged entrypoint the Runtime `load` path will open.
pub fn seal_staged_component(capsule: &Path, manifest: &[u8]) -> Result<StagedSeal, String> {
    seal_staged_bytes(&capsule.join(entrypoint(manifest)))
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

/// Size, offset and inode of `runtime/capability-requests.jsonl` at guest
/// launch. Readers use only bytes after `offset`. A changed inode after a
/// known file is a different file, not an append. A missing inode is not a
/// launch window: the file must stay absent until `elastos run` starts,
/// then the first inode seen during that run is the lock. `size` is the
/// real length at lock (and the max seen after that). A later shrink
/// FAILs.
#[derive(Clone, Debug)]
pub struct ReceiptCursor {
    pub path: PathBuf,
    pub inode: Option<u64>,
    pub size: u64,
    pub offset: u64,
}

/// Host-held snapshot of the receipt file at the end of `elastos run`.
/// `receipts_since_launch` judges this copy, not a later rewrite.
#[derive(Clone, Debug)]
pub struct ReceiptSeal {
    pub hash: String,
    pub inode: u64,
    pub size: u64,
    pub bytes: Vec<u8>,
}

/// Host-side name of the guest function that asked the bus. Required for
/// an A8 PASS. Written by the Runtime, never taken from guest stderr.
pub const GUEST_FUNCTION_JOURNAL_GRANTS: &str = "request_journal_grants";

/// Structured denial recorded by the Runtime on a manifest-bound ask.
pub const MANIFEST_DENIED: &str = "manifest_capability_denied";

/// Bindings this launch must print or return. Missing values are
/// NEEDS RUNTIME. A mismatch is a FAIL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchBind {
    pub assigned: Option<String>,
    pub session_id: Option<String>,
    pub guest_hash: String,
}

/// A fresh root from `mktemp -d` with its own HOME, data dir and TMPDIR.
/// `finish` removes it after a pass; a failed test keeps it.
pub struct Home {
    root: PathBuf,
    home: PathBuf,
    data: PathBuf,
    temp: PathBuf,
    finished: bool,
    launch_receipts: Mutex<Option<ReceiptCursor>>,
    receipt_seal: Mutex<Option<ReceiptSeal>>,
    used_sessions: Mutex<HashSet<String>>,
}

struct Spawned {
    child: Child,
    stdout: File,
    stderr: File,
}

fn mktemp_root() -> PathBuf {
    let mut command = Command::new("mktemp");
    command.arg("-d");
    if cfg!(target_os = "macos") {
        command.arg("-t").arg("a8-home");
    } else {
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        command.arg(format!("{tmp}/a8-home.XXXXXX"));
    }
    let output = command.output().expect("start mktemp");
    assert!(
        output.status.success(),
        "mktemp failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let path = String::from_utf8(output.stdout).expect("mktemp path is UTF-8");
    PathBuf::from(path.trim())
}

impl Home {
    pub fn new() -> Self {
        let root = mktemp_root();
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
            launch_receipts: Mutex::new(None),
            receipt_seal: Mutex::new(None),
            used_sessions: Mutex::new(HashSet::new()),
        }
    }

    /// Record a host-minted session once. A second insert is reuse.
    pub fn record_session(&self, session: &str) -> Result<(), String> {
        if !is_session_id(session) {
            return Err(format!(
                "session_id must be an unguessable per-launch id: {session}"
            ));
        }
        let mut used = self
            .used_sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !used.insert(session.to_string()) {
            return Err(format!("session_id reused across runs: {session}"));
        }
        Ok(())
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
        self.run_until(capsule, bound, |_| false)
    }

    /// Same as [`Home::run`], but stop as soon as `stop` is true. Used so a
    /// request that left the manifest bound (and went pending) fails on the
    /// host record instead of waiting out the client bound. The receipt file
    /// must still be absent at spawn; the first inode seen after that is the
    /// launch window.
    pub fn run_until(
        &self,
        capsule: &Path,
        bound: Duration,
        mut stop: impl FnMut(&Self) -> bool,
    ) -> Run {
        self.assert_receipts_absent();
        let mut spawned = self.spawn(&runtime().path, &["run", capsule.to_str().unwrap()]);
        let started = Instant::now();
        let status = loop {
            self.lock_launch_receipts();
            if let Some(status) = spawned.child.try_wait().expect("wait for elastos run") {
                break Some(status);
            }
            if stop(self) {
                stop_group(spawned.child.id());
                break spawned.child.wait().ok();
            }
            if started.elapsed() >= bound {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        self.lock_launch_receipts();
        self.seal_launch_receipts();
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

    pub fn receipts_path(&self) -> PathBuf {
        self.data.join("runtime/capability-requests.jsonl")
    }

    /// Fail if a leftover or planted receipt file is already in this Home.
    /// Called before the snapshot and again at spawn so the check covers
    /// the whole window from snapshot through `elastos run`. A dangling
    /// symlink is a planted journal: `exists()` misses it.
    pub fn assert_receipts_absent(&self) {
        let path = self.receipts_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => panic!(
                "capability-requests.jsonl must not exist before the guest is launched ({})",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("capability-requests.jsonl: {error}"),
        }
    }

    /// Record the real size and inode at first sight. A later shrink of
    /// that inode FAILs. Size 0 is only for a file that is still absent.
    pub fn lock_launch_receipts(&self) {
        let path = self.receipts_path();
        let Ok(meta) = fs::metadata(&path) else {
            return;
        };
        let mut guard = self
            .launch_receipts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cursor) = guard.as_mut() {
            if let Some(inode) = cursor.inode {
                if meta.ino() != inode {
                    panic!(
                        "capability-requests.jsonl inode changed after launch (was {inode}, now {})",
                        meta.ino()
                    );
                }
            }
            if meta.len() < cursor.size {
                panic!(
                    "capability-requests.jsonl shrank after launch (was {}, now {})",
                    cursor.size,
                    meta.len()
                );
            }
            cursor.size = meta.len();
            cursor.inode = Some(meta.ino());
            return;
        }
        *guard = Some(ReceiptCursor {
            path,
            inode: Some(meta.ino()),
            size: meta.len(),
            offset: 0,
        });
    }

    /// Snapshot the receipt bytes at the end of `elastos run`. Later
    /// rewrites of the same inode are judged against this copy.
    pub fn seal_launch_receipts(&self) {
        self.lock_launch_receipts();
        let guard = self
            .launch_receipts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(cursor) = guard.as_ref() else {
            return;
        };
        match seal_receipt_file(&cursor.path) {
            Ok(seal) => {
                *self.receipt_seal.lock().unwrap_or_else(|e| e.into_inner()) = Some(seal);
            }
            Err(reason) => panic!("{reason}"),
        }
    }

    /// Receipts the Runtime created during this `elastos run`. A file that
    /// appeared before spawn is refused by [`Home::assert_receipts_absent`].
    /// After `run_until` seals the file, a same-inode rewrite FAILs.
    /// A missing assigned id is not used here.
    pub fn receipts_since_launch(&self) -> Vec<CapabilityRequestRecord> {
        self.lock_launch_receipts();
        let sealed = self
            .receipt_seal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(seal) = sealed {
            return records_from_sealed_receipts(&seal, &self.receipts_path())
                .unwrap_or_else(|reason| panic!("{reason}"));
        }
        let guard = self
            .launch_receipts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(cursor) => self.capability_requests_since(cursor),
            None => Vec::new(),
        }
    }

    /// Runtime-authored text under this Home's data dir. Guest stderr is
    /// not included.
    pub fn host_runtime_log(&self) -> String {
        let mut text = String::new();
        let runtime_dir = self.data.join("runtime");
        let Ok(entries) = fs::read_dir(&runtime_dir) else {
            return text;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".jsonl") || name.ends_with(".log") {
                if let Ok(body) = fs::read_to_string(entry.path()) {
                    text.push_str(&body);
                    if !text.ends_with('\n') {
                        text.push('\n');
                    }
                }
            }
        }
        text
    }

    /// Record size and inode at launch. The file must be absent; size is 0
    /// and inode is none until the Runtime creates it.
    pub fn snapshot_receipts(&self) -> ReceiptCursor {
        let path = self.receipts_path();
        match fs::metadata(&path) {
            Ok(meta) => ReceiptCursor {
                path,
                inode: Some(meta.ino()),
                size: meta.len(),
                offset: meta.len(),
            },
            Err(_) => ReceiptCursor {
                path,
                inode: None,
                size: 0,
                offset: 0,
            },
        }
    }

    /// Host-side `request_capability` receipts the Runtime wrote under this
    /// Home. The guest has no filesystem and cannot add a row.
    pub fn capability_requests(&self) -> Vec<CapabilityRequestRecord> {
        self.capability_requests_since(&ReceiptCursor {
            path: self.receipts_path(),
            inode: None,
            size: 0,
            offset: 0,
        })
    }

    /// Only lines appended after `cursor`. A replaced inode after a known
    /// file is refused. Partial last lines are dropped.
    pub fn capability_requests_since(
        &self,
        cursor: &ReceiptCursor,
    ) -> Vec<CapabilityRequestRecord> {
        for _ in 0..8 {
            match read_capability_requests_since(cursor) {
                Ok(records) => return records,
                Err(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(Some(reason)) => panic!("{reason}"),
            }
        }
        Vec::new()
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
            eprintln!("retained throwaway root: {}", self.root.display());
        }
    }
}

/// One Runtime-authored `request_capability` receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRequestRecord {
    pub action: String,
    pub resource: String,
    pub code: String,
    pub capsule_id: Option<String>,
    pub principal_id: Option<String>,
    pub session_id: Option<String>,
    pub module_hash: Option<String>,
    pub guest_function: Option<String>,
    pub seq: Option<u64>,
}

fn optional_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn optional_seq(value: &serde_json::Value) -> Result<Option<u64>, String> {
    match value.get("seq") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| "receipt seq must be an unsigned integer".to_string())
            .map(Some),
        Some(_) => Err("receipt seq must be an unsigned integer".to_string()),
    }
}

struct UniqueObject(serde_json::Map<String, serde_json::Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueObject;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object with unique keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<UniqueObject, M::Error> {
                let mut object = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON key {key}")));
                    }
                    object.insert(key, value);
                }
                Ok(UniqueObject(object))
            }
        }
        deserializer.deserialize_map(UniqueVisitor)
    }
}

fn has_whitespace(text: &str) -> bool {
    text.bytes().any(|byte| byte.is_ascii_whitespace())
}

/// Parse one Runtime receipt line. Duplicate keys FAIL. Bind fields are
/// byte-exact: they are not trimmed. Hash aliases and guest stderr are ignored.
pub fn parse_capability_record(line: &str) -> Result<CapabilityRequestRecord, String> {
    let UniqueObject(object) = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let value = serde_json::Value::Object(object);
    Ok(CapabilityRequestRecord {
        action: value
            .get("action")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "receipt is missing action".to_string())?
            .to_string(),
        resource: value
            .get("resource")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "receipt is missing resource".to_string())?
            .to_string(),
        code: value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "receipt is missing code".to_string())?
            .to_string(),
        capsule_id: optional_string(&value, "capsule_id"),
        principal_id: optional_string(&value, "principal_id"),
        session_id: optional_string(&value, "session_id"),
        module_hash: optional_string(&value, "module_hash"),
        guest_function: optional_string(&value, "guest_function"),
        seq: optional_seq(&value)?,
    })
}

/// Isolation actions: resource plus the structured denial. Capsule id is
/// not a match here. A missing assigned id never turns this into a PASS.
pub fn isolation_denied_actions(
    records: &[CapabilityRequestRecord],
    resource: &str,
) -> Vec<String> {
    records
        .iter()
        .filter(|record| record.resource == resource && record.code == MANIFEST_DENIED)
        .map(|record| record.action.clone())
        .collect()
}

/// Binding actions. A missing assigned id matches nothing.
pub fn bound_denied_actions(
    records: &[CapabilityRequestRecord],
    resource: &str,
    assigned: Option<&str>,
) -> Vec<String> {
    let Some(id) = assigned else {
        return Vec::new();
    };
    records
        .iter()
        .filter(|record| {
            record.resource == resource
                && record.code == MANIFEST_DENIED
                && record.capsule_id.as_deref() == Some(id)
        })
        .map(|record| record.action.clone())
        .collect()
}

/// Guest function from host receipts or a Runtime log. Guest stderr is
/// ignored, including the Invalid follow sentence.
pub fn host_sequence_function(
    records: &[CapabilityRequestRecord],
    host_log: &str,
) -> Option<String> {
    if let Some(name) = records
        .iter()
        .find_map(|record| record.guest_function.clone())
    {
        return Some(name);
    }
    host_log.lines().find_map(|line| {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        optional_string(&value, "guest_function")
    })
}

/// Missing Runtime-ask fields (NEEDS RUNTIME) or a hard mismatch (FAIL).
/// Session must equal this launch's id, must be an unguessable 128-bit
/// hex minted host-side, and must not alias `capsule_id` or
/// `identity::context().session`. `module_hash` is the only hash field.
/// `guest_function` is required. `seq` must be strictly increasing.
pub fn authorship_gaps(
    records: &[CapabilityRequestRecord],
    bind: &LaunchBind,
) -> Result<Vec<&'static str>, String> {
    if records
        .iter()
        .any(|record| record.capsule_id.as_deref().is_some_and(has_whitespace))
    {
        return Err(format!(
            "capsule_id must be byte-exact; whitespace is refused; host records: {records:?}"
        ));
    }
    if records
        .iter()
        .any(|record| match (&record.session_id, &record.capsule_id) {
            (Some(session), Some(capsule)) => session == capsule,
            _ => false,
        })
    {
        return Err(format!(
            "session_id must not alias capsule_id or identity::context().session; host records: {records:?}"
        ));
    }
    if let Some(assigned) = bind.assigned.as_deref() {
        if bind.session_id.as_deref() == Some(assigned)
            || records
                .iter()
                .any(|record| record.session_id.as_deref() == Some(assigned))
        {
            return Err(format!(
                "session_id must not alias capsule_id or identity::context().session; host records: {records:?}"
            ));
        }
    }
    if records.iter().any(|record| {
        record
            .session_id
            .as_deref()
            .is_some_and(|session| !is_session_id(session))
    }) {
        return Err(format!(
            "session_id must be an unguessable per-launch id; host records: {records:?}"
        ));
    }
    if let Some(session) = bind.session_id.as_deref() {
        if !is_session_id(session) {
            return Err(format!(
                "session_id must be an unguessable per-launch id; host records: {records:?}"
            ));
        }
    }
    refuse_seq(records)?;
    if let Some(id) = bind.assigned.as_deref() {
        if records
            .iter()
            .any(|record| record.capsule_id.as_deref() != Some(id))
        {
            return Err(format!(
                "receipt capsule_id must match this launch {id}; host records: {records:?}"
            ));
        }
    }
    if let Some(session) = bind.session_id.as_deref() {
        if records
            .iter()
            .any(|record| record.session_id.as_deref() != Some(session))
        {
            return Err(format!(
                "receipt session_id must equal this launch {session}; host records: {records:?}"
            ));
        }
    }
    if records.iter().any(|record| {
        record
            .module_hash
            .as_deref()
            .is_some_and(|hash| hash != bind.guest_hash)
    }) {
        return Err(format!(
            "receipt module_hash must equal this guest {}; host records: {records:?}",
            bind.guest_hash
        ));
    }
    if records.iter().any(|record| {
        record
            .guest_function
            .as_deref()
            .is_some_and(|name| name != GUEST_FUNCTION_JOURNAL_GRANTS)
    }) {
        return Err(format!(
            "honest sequence requires request_journal_grants on host receipts; host records: {records:?}"
        ));
    }

    let mut missing = Vec::new();
    if bind.assigned.is_none() {
        missing.push("component id from Runtime [run] output or API");
    }
    if bind.session_id.is_none()
        || records.is_empty()
        || records.iter().any(|record| record.session_id.is_none())
    {
        missing.push("session id");
    }
    if records.is_empty()
        || records
            .iter()
            .any(|record| record.module_hash.as_deref() != Some(bind.guest_hash.as_str()))
    {
        missing.push("guest module hash");
    }
    if records.is_empty()
        || records
            .iter()
            .any(|record| record.guest_function.as_deref() != Some(GUEST_FUNCTION_JOURNAL_GRANTS))
    {
        missing.push("guest function");
    }
    if records.is_empty() || records.iter().any(|record| record.seq.is_none()) {
        missing.push("receipt seq");
    }
    if records.len() != 2 {
        missing.push("write-then-read pair");
    }
    Ok(missing)
}

fn refuse_seq(records: &[CapabilityRequestRecord]) -> Result<(), String> {
    if records.iter().all(|record| record.seq.is_none()) {
        return Ok(());
    }
    if records.iter().any(|record| record.seq.is_none()) {
        return Err(format!(
            "receipt seq is missing on some lines; host records: {records:?}"
        ));
    }
    let nums: Vec<u64> = records.iter().map(|record| record.seq.unwrap()).collect();
    for pair in nums.windows(2) {
        match pair[0].checked_add(1) {
            Some(next) if pair[1] == next => {}
            _ => {
                return Err(format!(
                    "receipt seq must be strictly increasing without gaps or repeats; wrap at u64::MAX is refused; host records: {records:?}"
                ));
            }
        }
    }
    Ok(())
}

pub fn read_capability_requests_since(
    cursor: &ReceiptCursor,
) -> Result<Vec<CapabilityRequestRecord>, Option<String>> {
    let meta = match fs::metadata(&cursor.path) {
        Ok(meta) => meta,
        Err(_) => return Err(None),
    };
    if let Some(inode) = cursor.inode {
        if meta.ino() != inode {
            return Err(Some(format!(
                "capability-requests.jsonl inode changed after launch (was {inode}, now {})",
                meta.ino()
            )));
        }
        if meta.len() < cursor.size {
            return Err(Some(format!(
                "capability-requests.jsonl shrank after launch (was {}, now {})",
                cursor.size,
                meta.len()
            )));
        }
    }
    let mut file = File::open(&cursor.path).map_err(|_| None)?;
    file.seek(SeekFrom::Start(cursor.offset))
        .map_err(|_| None)?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|_| None)?;
    if text.as_bytes().starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(Some(
            "capability-requests.jsonl must not start with a BOM".into(),
        ));
    }
    if !text.is_empty() && !text.ends_with('\n') {
        if let Some(last) = text.rfind('\n') {
            text.truncate(last + 1);
        } else {
            text.clear();
        }
    }
    let mut records = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_capability_record(line) {
            Ok(record) => records.push(record),
            Err(reason) => return Err(Some(reason)),
        }
    }
    Ok(records)
}

/// Snapshot the receipt file bytes. Used at the end of `elastos run`.
pub fn seal_receipt_file(path: &Path) -> Result<ReceiptSeal, String> {
    let meta = fs::metadata(path)
        .map_err(|error| format!("capability-requests.jsonl could not be sealed: {error}"))?;
    let bytes = fs::read(path)
        .map_err(|error| format!("capability-requests.jsonl could not be sealed: {error}"))?;
    Ok(ReceiptSeal {
        hash: sha256(&bytes),
        inode: meta.ino(),
        size: meta.len(),
        bytes,
    })
}

/// Judge the sealed copy. A same-inode rewrite after `run_until` FAILs.
pub fn records_from_sealed_receipts(
    seal: &ReceiptSeal,
    path: &Path,
) -> Result<Vec<CapabilityRequestRecord>, String> {
    let meta = fs::metadata(path)
        .map_err(|error| format!("capability-requests.jsonl rewritten after run ({error})"))?;
    if meta.ino() != seal.inode {
        return Err(format!(
            "capability-requests.jsonl inode changed after launch (was {}, now {})",
            seal.inode,
            meta.ino()
        ));
    }
    if meta.len() < seal.size {
        return Err(format!(
            "capability-requests.jsonl shrank after launch (was {}, now {})",
            seal.size,
            meta.len()
        ));
    }
    if seal.bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err("capability-requests.jsonl must not start with a BOM".into());
    }
    if !seal.bytes.is_empty() && !seal.bytes.ends_with(b"\n") {
        return Err("capability-requests.jsonl truncated final line".into());
    }
    let current = fs::read(path).map_err(|error| error.to_string())?;
    if meta.len() != seal.size || sha256(&current) != seal.hash {
        return Err(
            "capability-requests.jsonl rewritten after run; host receipts are the sealed copy"
                .to_string(),
        );
    }
    let cursor = ReceiptCursor {
        path: path.to_path_buf(),
        inode: Some(seal.inode),
        size: seal.size,
        offset: 0,
    };
    match read_capability_requests_since(&cursor) {
        Ok(records) => Ok(records),
        Err(Some(reason)) => Err(reason),
        Err(None) => Ok(Vec::new()),
    }
}

/// The component id the Runtime printed on a `[run]` line. Guest-controlled
/// error text is ignored.
pub fn assigned_component_id(text: &str) -> Option<String> {
    text.lines()
        .filter(|line| line.starts_with("[run] "))
        .find_map(|line| {
            line.split(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == ',')
                .find(|word| is_component_id(word))
                .map(str::to_string)
        })
}

/// The session id the Runtime printed on a `[run]` line. Presence of any
/// non-empty string on a receipt is not a bind. `session-1` and
/// `identity::context().session` (`capsule_id`) are not a bind.
pub fn assigned_session_id(text: &str) -> Option<String> {
    text.lines()
        .filter(|line| line.starts_with("[run] "))
        .find_map(|line| {
            for word in line.split(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == ',')
            {
                if let Some(value) = word.strip_prefix("session_id=") {
                    if is_session_id(value) {
                        return Some(value.to_string());
                    }
                }
                if is_session_id(word) {
                    return Some(word.to_string());
                }
            }
            None
        })
}

/// Unguessable per-launch id: 32 lowercase hex digits (128 bits), minted
/// host-side from a CSPRNG. Optional `session-` prefix. `session-1` is
/// refused. Values below `2^64` are time, pid, or zero derived.
pub fn is_session_id(word: &str) -> bool {
    let hex = word.strip_prefix("session-").unwrap_or(word);
    if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return false;
    }
    let Ok(value) = u128::from_str_radix(hex, 16) else {
        return false;
    };
    value >= (1u128 << 64)
}

/// Mint a 128-bit session from the host CSPRNG. Record it with
/// [`Home::record_session`] so it cannot be reused across runs.
pub fn mint_session_id() -> String {
    for _ in 0..8 {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .expect("read the host CSPRNG");
        let value = u128::from_be_bytes(bytes);
        if value >= (1u128 << 64) {
            return format!("{value:032x}");
        }
    }
    panic!("host CSPRNG did not yield a 128-bit session")
}

fn is_component_id(word: &str) -> bool {
    let Some(rest) = word.strip_prefix("component-") else {
        return false;
    };
    let mut parts = rest.split('-');
    matches!(
        (
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next().map(str::len),
            parts.next(),
        ),
        (Some(8), Some(4), Some(4), Some(4), Some(12), None)
    ) && rest.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
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

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE: &str = "localhost://Public/../../../../.ssh/id_ed25519";
    const HASH: &str = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737";
    const ASSIGNED: &str = "component-341af27a-6b9c-4892-a618-808f0b687a9d";
    const FOREIGN: &str = "component-00000000-0000-0000-0000-000000000000";
    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn denied(action: &str, capsule: &str) -> String {
        format!(
            r#"{{"action":"{action}","capsule_id":"{capsule}","code":"{MANIFEST_DENIED}","principal_id":null,"resource":"{RESOURCE}"}}"#
        )
    }

    fn honest_today() -> Vec<CapabilityRequestRecord> {
        ["write", "read"]
            .into_iter()
            .map(|action| parse_capability_record(&denied(action, ASSIGNED)).unwrap())
            .collect()
    }

    fn bind(assigned: Option<&str>, session: Option<&str>) -> LaunchBind {
        LaunchBind {
            assigned: assigned.map(str::to_string),
            session_id: session.map(str::to_string),
            guest_hash: HASH.to_string(),
        }
    }

    #[test]
    fn missing_assigned_is_not_a_match() {
        let records = honest_today();
        assert_eq!(
            isolation_denied_actions(&records, RESOURCE),
            ["write", "read"]
        );
        assert!(bound_denied_actions(&records, RESOURCE, None).is_empty());
        let missing = authorship_gaps(&records, &bind(None, None)).unwrap();
        assert!(missing.contains(&"component id from Runtime [run] output or API"));
        assert!(missing.contains(&"session id"));
        assert!(missing.contains(&"guest module hash"));
        assert!(missing.contains(&"guest function"));
        assert!(missing.contains(&"receipt seq"));
    }

    #[test]
    fn foreign_capsule_id_is_a_fail() {
        let records: Vec<_> = ["write", "read"]
            .into_iter()
            .map(|action| parse_capability_record(&denied(action, FOREIGN)).unwrap())
            .collect();
        let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(SESSION))).unwrap_err();
        assert!(err.contains("receipt capsule_id must match this launch"));
    }

    #[test]
    fn session_must_equal_this_launch() {
        let mut records = honest_today();
        for record in &mut records {
            record.session_id = Some("fedcba9876543210fedcba9876543210".into());
            record.module_hash = Some(HASH.into());
            record.guest_function = Some(GUEST_FUNCTION_JOURNAL_GRANTS.into());
        }
        let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(SESSION))).unwrap_err();
        assert!(err.contains("receipt session_id must equal this launch"));
    }

    #[test]
    fn guest_function_is_required_and_must_be_journal_grants() {
        let mut records = honest_today();
        for record in &mut records {
            record.session_id = Some(SESSION.into());
            record.module_hash = Some(HASH.into());
            record.guest_function = Some("capabilities::request".into());
        }
        let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(SESSION))).unwrap_err();
        assert!(err.contains("honest sequence requires request_journal_grants"));
    }

    #[test]
    fn hash_aliases_are_not_module_hash() {
        let line = format!(
            r#"{{"action":"write","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","resource":"{RESOURCE}","session_id":"{SESSION}","wasm_hash":"{HASH}","guest_hash":"{HASH}"}}"#
        );
        let record = parse_capability_record(&line).unwrap();
        assert!(record.module_hash.is_none());
        let missing = authorship_gaps(&[record], &bind(Some(ASSIGNED), Some(SESSION))).unwrap();
        assert!(missing.contains(&"guest module hash"));
        assert!(missing.contains(&"guest function"));
        assert!(missing.contains(&"receipt seq"));
    }

    #[test]
    fn follow_sentence_is_not_host_sequence() {
        let records = honest_today();
        assert!(
            host_sequence_function(&records, "the journal append did not follow its grants")
                .is_none()
        );
        let log = format!(r#"{{"guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}"}}"#);
        assert_eq!(
            host_sequence_function(&[], &log).as_deref(),
            Some(GUEST_FUNCTION_JOURNAL_GRANTS)
        );
    }

    #[test]
    fn session_id_comes_from_run_lines_only() {
        assert!(assigned_session_id(
            "the journal append did not follow its grants\nsession-sneak\n"
        )
        .is_none());
        assert_eq!(
            assigned_session_id(&format!(
                "[run] Component capsule attached session_id={SESSION}"
            ))
            .as_deref(),
            Some(SESSION)
        );
        assert!(assigned_session_id("[run] session_id=session-1").is_none());
        assert!(assigned_session_id(&format!("[run] session_id={ASSIGNED}")).is_none());
        assert!(assigned_component_id(
            "guest printed component-00000000-0000-0000-0000-000000000000\n"
        )
        .is_none());
        assert_eq!(
            assigned_component_id(&format!("[run] Component capsule attached {ASSIGNED}"))
                .as_deref(),
            Some(ASSIGNED)
        );
    }

    #[test]
    fn complete_bind_has_no_gaps() {
        let mut records = honest_today();
        for record in &mut records {
            record.session_id = Some(SESSION.into());
            record.module_hash = Some(HASH.into());
            record.guest_function = Some(GUEST_FUNCTION_JOURNAL_GRANTS.into());
        }
        records[0].seq = Some(1);
        records[1].seq = Some(2);
        assert!(
            authorship_gaps(&records, &bind(Some(ASSIGNED), Some(SESSION)))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            bound_denied_actions(&records, RESOURCE, Some(ASSIGNED)),
            ["write", "read"]
        );
    }
}
