//! wc-005: verify a bundle, then run the exact verified bytes of its core
//! module under two independent host engines and require the same output.
//!
//! [`run`] does these steps, in order, and stops at the first refusal:
//!
//! 1. wc-004's [`verify_bundle`], with no grants: the one verify path. A
//!    refusal is the verifier's own, and no engine starts.
//! 2. A new OUT_DIR, and inside it a new `staged/` folder holding every entry
//!    of the verified value's `entries()`: the checked bytes, never a re-read
//!    of the bundle. Staging works through folder handles: every folder is
//!    made new by this run (`mkdirat`) and opened without following a link
//!    (`O_NOFOLLOW`), and every file is made new in its folder's handle
//!    (`O_EXCL`). So staging never writes into a folder it did not make, nor
//!    through a link, and never outside OUT_DIR.
//! 3. The staged module is sealed: the runner keeps the handles it made for
//!    the staged folder, each folder on the entrypoint's path and the module
//!    file, and records each one's inode and change time. Each name on that
//!    path must lead to the handle the runner made, so an entry replaced
//!    before sealing, even with the same bytes, is refused too.
//! 4. [`crate::bundle_identity`] of the staged copy, compared with the
//!    verified value's `cid()`. A mismatch stops the run before either engine
//!    starts.
//! 5. Each engine's `--version`, recorded as the engine printed it.
//! 6. `wasmtime run --invoke` and then `wasmer run --invoke` of the staged
//!    entrypoint module, with the fixed [`INVOKE_FUNCTION`] and
//!    [`INVOKE_ARGUMENTS`]: two separate processes, one after the other,
//!    neither inside the other, with no directory, environment or network
//!    flag. Each engine starts in the sealed staged folder (`fchdir` on the
//!    runner's own handle, in the child only) and gets the module as
//!    `./<entrypoint>`: no part of OUT_DIR reaches its command line, and the
//!    argument can never be read as an option.
//! 7. The seal is checked before each engine starts and after the last one
//!    exits. Each name on the module's path must still lead to the sealed
//!    inode, and no sealed inode's change time may move. Any write, rename,
//!    link or mode change moves a change time, and no unprivileged process
//!    can set one back, so a module changed or swapped and restored at any
//!    time after sealing is refused.
//! 8. Both engines must exit successfully, and their stdout must match byte
//!    for byte.
//! 9. A new `receipt.txt`, made in OUT_DIR's handle, records the lab CID, both
//!    observed engine versions, the function, the arguments and both outputs.
//!
//! The engines are inputs ([`Engines`]), never read from the environment, so
//! a test points the runner at a stand-in engine. There is one run path: the
//! input chooses which program starts, not what the runner does.
//!
//! Both engines are test-only host engines; neither is endorsed. The result is
//! a behaviour proof on one core module, never a claim about the Component
//! ABI. The runner makes no admission, launch or publisher-trust decision.
//! It reads no environment variable and parses no manifest or module: the
//! verified value already says which entry is the module. Links in OUT_DIR's
//! own parent folders are not checked.

use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};

use capsule_identity::{BundleEntry, LabCid, NameSignature, Refusal as IdentityRefusal};

use crate::bundle::path_to_run;
use crate::bundle_identity;
use crate::verify::{verify_bundle, VerifyRefusal};

/// The capsule's one export, invoked on both engines.
pub const INVOKE_FUNCTION: &str = "digest";

/// The fixed arguments `digest` is invoked with: the capsule's `FIXED_INPUT`,
/// `0x5EED_0001`, in decimal. Both engines get exactly these.
pub const INVOKE_ARGUMENTS: &[&str] = &["1592590337"];

/// The receipt's schema line.
pub const RECEIPT_SCHEMA: &str = "wc-005.run-receipt/v1";

/// The folder inside OUT_DIR that holds the staged copy.
const STAGED_DIR: &str = "staged";

/// The receipt's file name inside OUT_DIR.
const RECEIPT_FILE: &str = "receipt.txt";

/// How a staged folder is opened: a folder only, never through a link.
const FOLDER_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// How a staged file or the receipt is made: new, never through a link.
const NEW_FILE_FLAGS: libc::c_int =
    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// The two host engines, each by the path of its program. Both are test-only
/// host engines; neither is endorsed.
#[derive(Clone, Copy, Debug)]
pub struct Engines<'a> {
    pub wasmtime: &'a Path,
    pub wasmer: &'a Path,
}

/// Which of the two engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Wasmtime,
    Wasmer,
}

impl Engine {
    /// The flags before the module path. Each engine has its own command
    /// line; neither gets a directory, environment or network flag.
    fn run_flags(self) -> &'static [&'static str] {
        match self {
            Engine::Wasmtime => &["run", "--invoke", INVOKE_FUNCTION],
            Engine::Wasmer => &["run", "--invoke", INVOKE_FUNCTION],
        }
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Engine::Wasmtime => write!(f, "wasmtime"),
            Engine::Wasmer => write!(f, "wasmer"),
        }
    }
}

/// When the runner tells its observer about OUT_DIR or the staged folder.
/// The observer gets the moment and the path it is about and returns
/// nothing, so it cannot steer the run. Tests use it to change the folder at
/// that moment, as another process could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// OUT_DIR is made and not opened yet. The path is OUT_DIR.
    OutDirMade,
    /// The staged folder is made; no entry is written yet. The path is the
    /// staged folder.
    StagedFolderMade,
    /// Every entry is written; the module is not sealed and the copy is not
    /// named yet. The path is the staged folder.
    EntriesStaged,
}

/// Why a run was refused. Each step has its own reason.
#[derive(Debug)]
pub enum Reason {
    /// wc-004's verifier refused the bundle: its own refusal, unchanged.
    Verify(VerifyRefusal),
    /// Something is already at OUT_DIR.
    OutDirExists,
    /// OUT_DIR could not be made.
    OutDirNotCreated(io::Error),
    /// The OUT_DIR the runner made could not be opened as a folder without
    /// following a link: something replaced it.
    OutDirNotOpened(io::Error),
    /// A folder of the staged copy could not be made new, or opened.
    FolderNotStaged(io::Error),
    /// A verified entry could not be written into the staged copy.
    EntryNotStaged(io::Error),
    /// A sealed handle's own state could not be read.
    ModuleNotSealed(io::Error),
    /// [`crate::bundle_identity`] refused the staged copy: its own refusal.
    StagedNotNamed(IdentityRefusal),
    /// The staged copy's lab CID is not the verified one.
    StagedNameMismatch { verified: LabCid, staged: LabCid },
    /// The staged module, or a folder on its path, changed after it was
    /// sealed.
    StagedModuleChanged,
    /// An engine's `--version` could not be started.
    VersionNotQueried { engine: Engine, cause: io::Error },
    /// An engine's `--version` ran and failed.
    VersionQueryFailed { engine: Engine, status: ExitStatus },
    /// An engine could not be started to run the module.
    EngineNotStarted { engine: Engine, cause: io::Error },
    /// An engine ran the module and did not exit successfully.
    EngineFailed {
        engine: Engine,
        status: ExitStatus,
        stderr: Vec<u8>,
    },
    /// Both engines exited successfully, with different stdout.
    OutputsDiffer { wasmtime: Vec<u8>, wasmer: Vec<u8> },
    /// The receipt could not be made new or written.
    ReceiptNotWritten(io::Error),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Verify(refusal) => write!(f, "not verified, no engine started: {refusal}"),
            Reason::OutDirExists => write!(
                f,
                "OUT_DIR already exists: the runner makes a new OUT_DIR and never writes into or through what is already there"
            ),
            Reason::OutDirNotCreated(cause) => write!(f, "OUT_DIR cannot be created: {cause}"),
            Reason::OutDirNotOpened(cause) => write!(
                f,
                "the OUT_DIR the runner made cannot be opened as a folder without following a link: {cause}"
            ),
            Reason::FolderNotStaged(cause) => {
                write!(f, "a staged folder cannot be created: {cause}")
            }
            Reason::EntryNotStaged(cause) => {
                write!(f, "a verified entry cannot be staged: {cause}")
            }
            Reason::ModuleNotSealed(cause) => {
                write!(f, "the staged module cannot be sealed or checked: {cause}")
            }
            Reason::StagedNotNamed(refusal) => {
                write!(f, "the staged copy gets no lab CID: {refusal}")
            }
            Reason::StagedNameMismatch { verified, staged } => write!(
                f,
                "the staged copy is named {staged}, not the verified {verified}: no engine started"
            ),
            Reason::StagedModuleChanged => write!(
                f,
                "the staged module or a folder on its path changed after it was sealed: no further engine started and no receipt written"
            ),
            Reason::VersionNotQueried { engine, cause } => {
                write!(f, "{engine} --version did not start: {cause}")
            }
            Reason::VersionQueryFailed { engine, status } => {
                write!(f, "{engine} --version failed ({status})")
            }
            Reason::EngineNotStarted { engine, cause } => {
                write!(f, "{engine} did not start: {cause}")
            }
            Reason::EngineFailed {
                engine,
                status,
                stderr,
            } => write!(
                f,
                "{engine} failed ({status}); its stderr: {:?}",
                String::from_utf8_lossy(stderr)
            ),
            Reason::OutputsDiffer { wasmtime, wasmer } => write!(
                f,
                "the engines' stdout differs: wasmtime {:?}, wasmer {:?}",
                String::from_utf8_lossy(wasmtime),
                String::from_utf8_lossy(wasmer)
            ),
            Reason::ReceiptNotWritten(cause) => {
                write!(f, "the receipt cannot be written: {cause}")
            }
        }
    }
}

/// A refused run: the path it stopped at, and why.
#[derive(Debug)]
pub struct RunRefusal {
    pub path: PathBuf,
    pub reason: Reason,
}

impl RunRefusal {
    fn new(path: &Path, reason: Reason) -> RunRefusal {
        RunRefusal {
            path: path.to_path_buf(),
            reason,
        }
    }
}

impl fmt::Display for RunRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

impl std::error::Error for RunRefusal {}

/// A run both engines agreed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoEngineRun {
    /// The verified lab CID, which the staged copy also has.
    pub cid: LabCid,
    /// The stdout both engines printed.
    pub stdout: Vec<u8>,
    /// What `wasmtime --version` printed.
    pub wasmtime_version: String,
    /// What `wasmer --version` printed.
    pub wasmer_version: String,
    /// The receipt's path, `OUT_DIR/receipt.txt`.
    pub receipt: PathBuf,
}

/// One engine's run of the module.
struct EngineRun {
    engine: Engine,
    path: PathBuf,
    output: Output,
}

/// Verify `bundle` against `signature` and the `accepted` signer DIDs, then
/// run it on both `engines`, staging into the new folder `out_dir`. This is
/// [`run_observed`] with an observer that does nothing: the same run, not a
/// second one.
pub fn run(
    bundle: &Path,
    signature: Option<&NameSignature>,
    accepted: &[String],
    engines: Engines<'_>,
    out_dir: &Path,
) -> Result<TwoEngineRun, RunRefusal> {
    run_observed(bundle, signature, accepted, engines, out_dir, |_, _| {})
}

/// [`run`], telling `observe` about OUT_DIR and the staged folder at each
/// [`Moment`].
pub fn run_observed(
    bundle: &Path,
    signature: Option<&NameSignature>,
    accepted: &[String],
    engines: Engines<'_>,
    out_dir: &Path,
    mut observe: impl FnMut(Moment, &Path),
) -> Result<TwoEngineRun, RunRefusal> {
    let verified = verify_bundle(bundle, signature, accepted, &[])
        .map_err(|refusal| RunRefusal::new(bundle, Reason::Verify(refusal)))?;
    let (cid, entries, entrypoint) = (verified.cid(), verified.entries(), verified.entrypoint());
    let staged = stage(entries, &entrypoint.path, out_dir, &mut observe)?;
    check_staged_name(&staged.path, cid)?;
    let module = module_argument(&entrypoint.path);

    let wasmtime_version = query_version(Engine::Wasmtime, engines.wasmtime)?;
    let wasmer_version = query_version(Engine::Wasmer, engines.wasmer)?;
    let wasmtime = run_engine(Engine::Wasmtime, engines.wasmtime, &staged, &module)?;
    let wasmer = run_engine(Engine::Wasmer, engines.wasmer, &staged, &module)?;
    staged.check_unchanged()?;
    compare(&wasmtime, &wasmer, &staged.path.join(&entrypoint.path))?;

    let receipt = out_dir.join(RECEIPT_FILE);
    let text = receipt_text(
        cid,
        &entrypoint.path,
        &wasmtime_version,
        &wasmer_version,
        &wasmtime,
        &wasmer,
    );
    write_new_file(&staged.out, RECEIPT_FILE, text.as_bytes())
        .map_err(|cause| RunRefusal::new(&receipt, Reason::ReceiptNotWritten(cause)))?;
    Ok(TwoEngineRun {
        cid,
        stdout: wasmtime.output.stdout,
        wasmtime_version,
        wasmer_version,
        receipt,
    })
}

/// One sealed step on the module's path: a handle, its path under the staged
/// folder, its name in the step before it, and its state when sealed.
struct Sealed {
    relative: String,
    name: CString,
    handle: File,
    state: State,
}

/// What a sealed handle is and when it last changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl State {
    fn of(handle: &File) -> io::Result<State> {
        let meta = handle.metadata()?;
        Ok(State {
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }
}

/// The staged copy: OUT_DIR's handle, the staged folder's path, and the
/// sealed steps from the staged folder to the module file. The first step is
/// the staged folder; each engine starts in it.
struct Staged {
    out: File,
    path: PathBuf,
    module: Vec<Sealed>,
}

impl Staged {
    /// The handle each engine starts in.
    fn folder(&self) -> &File {
        &self.module[0].handle
    }

    /// Each sealed step must be unchanged, and each name must still lead to
    /// the sealed step after it, never through a link.
    fn check_unchanged(&self) -> Result<(), RunRefusal> {
        for (at, step) in self.module.iter().enumerate() {
            let path = match step.relative.as_str() {
                "" => self.path.clone(),
                relative => self.path.join(relative),
            };
            let now = State::of(&step.handle)
                .map_err(|cause| RunRefusal::new(&path, Reason::ModuleNotSealed(cause)))?;
            let linked = match at.checked_sub(1) {
                None => true,
                Some(before) => entry_is(&self.module[before].handle, &step.name, now),
            };
            if now != step.state || !linked {
                return Err(RunRefusal::new(&path, Reason::StagedModuleChanged));
            }
        }
        Ok(())
    }
}

/// Make the new `out_dir` and its new staged folder, write every verified
/// entry into it, and seal the module `entrypoint`.
fn stage(
    entries: &[BundleEntry],
    entrypoint: &str,
    out_dir: &Path,
    observe: &mut impl FnMut(Moment, &Path),
) -> Result<Staged, RunRefusal> {
    // `create_dir` refuses anything already at OUT_DIR, a link included.
    fs::create_dir(out_dir).map_err(|cause| match cause.kind() {
        io::ErrorKind::AlreadyExists => RunRefusal::new(out_dir, Reason::OutDirExists),
        _ => RunRefusal::new(out_dir, Reason::OutDirNotCreated(cause)),
    })?;
    observe(Moment::OutDirMade, out_dir);
    let out = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(out_dir)
        .map_err(|cause| RunRefusal::new(out_dir, Reason::OutDirNotOpened(cause)))?;
    let path = out_dir.join(STAGED_DIR);
    let staged = new_folder(&out, STAGED_DIR)
        .map_err(|cause| RunRefusal::new(&path, Reason::FolderNotStaged(cause)))?;
    observe(Moment::StagedFolderMade, &path);

    let mut folders = HashMap::new();
    let mut files = HashMap::new();
    for entry in entries {
        let file = stage_entry(&staged, &path, &mut folders, entry)?;
        files.insert(entry.path.clone(), file);
    }
    observe(Moment::EntriesStaged, &path);
    let module = seal(staged, folders, files, entrypoint)
        .map_err(|cause| RunRefusal::new(&path, Reason::ModuleNotSealed(cause)))?;
    Ok(Staged { out, path, module })
}

/// Write one verified entry's checked bytes at its path under the staged
/// folder `staged`, at `root`, making its folders first. The path comes from
/// cc-capsule-identity's one walk: bundle-relative and `/`-separated.
/// Returns the new file's handle.
fn stage_entry(
    staged: &File,
    root: &Path,
    folders: &mut HashMap<String, File>,
    entry: &BundleEntry,
) -> Result<File, RunRefusal> {
    let (folder, name) = match entry.path.rsplit_once('/') {
        Some((folder, name)) => (Some(folder), name),
        None => (None, entry.path.as_str()),
    };
    if let Some(folder) = folder {
        stage_folders(staged, root, folders, folder)?;
    }
    let parent = folder.map_or(staged, |folder| &folders[folder]);
    let path = root.join(&entry.path);
    let mut file = new_file(parent, name)
        .map_err(|cause| RunRefusal::new(&path, Reason::EntryNotStaged(cause)))?;
    file.write_all(&entry.content)
        .and_then(|()| file.flush())
        .map_err(|cause| RunRefusal::new(&path, Reason::EntryNotStaged(cause)))?;
    Ok(file)
}

/// Make each folder on `folder`'s path that this run has not made yet, each
/// in its parent's handle, and keep its handle in `folders` by its path.
fn stage_folders(
    staged: &File,
    root: &Path,
    folders: &mut HashMap<String, File>,
    folder: &str,
) -> Result<(), RunRefusal> {
    let mut parent: Option<&str> = None;
    for (at, _) in folder.match_indices('/').chain([(folder.len(), "")]) {
        let relative = &folder[..at];
        if !folders.contains_key(relative) {
            let name = parent.map_or(relative, |parent| &relative[parent.len() + 1..]);
            let handle = new_folder(parent.map_or(staged, |parent| &folders[parent]), name)
                .map_err(|cause| {
                    RunRefusal::new(&root.join(relative), Reason::FolderNotStaged(cause))
                })?;
            folders.insert(relative.to_owned(), handle);
        }
        parent = Some(relative);
    }
    Ok(())
}

/// The sealed steps from the staged folder to the module `entrypoint`.
fn seal(
    staged: File,
    mut folders: HashMap<String, File>,
    mut files: HashMap<String, File>,
    entrypoint: &str,
) -> io::Result<Vec<Sealed>> {
    let mut steps = vec![(String::new(), String::new(), staged)];
    for (at, _) in entrypoint.match_indices('/') {
        let relative = &entrypoint[..at];
        steps.push((
            relative.to_owned(),
            last_name(relative),
            take(&mut folders, relative)?,
        ));
    }
    let module = take(&mut files, entrypoint)?;
    steps.push((entrypoint.to_owned(), last_name(entrypoint), module));
    steps
        .into_iter()
        .map(|(relative, name, handle)| {
            Ok(Sealed {
                relative,
                name: c_name(&name)?,
                state: State::of(&handle)?,
                handle,
            })
        })
        .collect()
}

/// The last `/`-separated name of `relative`.
fn last_name(relative: &str) -> String {
    relative.rsplit('/').next().unwrap_or(relative).to_owned()
}

/// The handle staged at `relative`. The verifier found the entrypoint among
/// the entries, so it is always there.
fn take(handles: &mut HashMap<String, File>, relative: &str) -> io::Result<File> {
    handles.remove(relative).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{relative:?} was not staged"),
        )
    })
}

/// `name` as a C string. A name from the walk never holds a NUL byte.
fn c_name(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL byte"))
}

/// Make the new folder `name` in the folder `parent` and open it, never
/// through a link. A folder already there, whoever made it, is refused.
fn new_folder(parent: &File, name: &str) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: `parent` is an open folder handle and `name` a NUL-terminated
    // string; mkdirat reads both and keeps neither.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
        return Err(io::Error::last_os_error());
    }
    open_at(parent, &name, FOLDER_FLAGS, 0)
}

/// Make the new file `name` in the folder `parent`, never through a link.
fn new_file(parent: &File, name: &str) -> io::Result<File> {
    open_at(parent, &c_name(name)?, NEW_FILE_FLAGS, 0o644)
}

/// `openat` in `parent`, as an owned handle.
fn open_at(
    parent: &File,
    name: &CString,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> io::Result<File> {
    // SAFETY: `parent` is an open folder handle and `name` a NUL-terminated
    // string; openat reads both and keeps neither.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened here and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Whether `name` in the folder `parent`, not followed if it is a link, is
/// the inode `expected` describes. A name that is gone is not.
fn entry_is(parent: &File, name: &CString, expected: State) -> bool {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `parent` is an open folder handle, `name` a NUL-terminated
    // string and `stat` room for one `stat`, which fstatat fills on success.
    let found = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found != 0 {
        return false;
    }
    // SAFETY: fstatat succeeded, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    stat.st_dev as u64 == expected.dev && stat.st_ino as u64 == expected.ino
}

/// Make the new file `name` in the folder `parent` and write `bytes` into it.
fn write_new_file(parent: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = new_file(parent, name)?;
    file.write_all(bytes).and_then(|()| file.flush())
}

/// The staged copy's lab CID, through the one export, must be the verified
/// one. The two are compared as opaque values.
fn check_staged_name(staged: &Path, verified: LabCid) -> Result<(), RunRefusal> {
    let copy = bundle_identity(staged)
        .map_err(|refusal| RunRefusal::new(staged, Reason::StagedNotNamed(refusal)))?;
    if copy != verified {
        return Err(RunRefusal::new(
            staged,
            Reason::StagedNameMismatch {
                verified,
                staged: copy,
            },
        ));
    }
    Ok(())
}

/// The module as each engine gets it: `./` and the entrypoint's path, read
/// from the staged folder the engine starts in. It starts with `.`, so no
/// engine reads it as an option, and it holds no part of OUT_DIR.
fn module_argument(entrypoint: &str) -> OsString {
    OsString::from(format!("./{entrypoint}"))
}

/// Start the program at `path` with `args`, by its path, and wait for it.
/// With `folder`, the child starts in that open folder handle. The one place
/// the runner starts a process.
fn start(path: &Path, args: &[OsString], folder: Option<&File>) -> io::Result<Output> {
    let mut command = Command::new(path_to_run(path));
    command.args(args).stdin(Stdio::null());
    if let Some(folder) = folder {
        let fd = folder.as_raw_fd();
        // SAFETY: in the child, between fork and exec, the hook only calls
        // fchdir, which is async-signal-safe, on a handle this process holds
        // open for the whole call.
        unsafe {
            command.pre_exec(move || match libc::fchdir(fd) {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            });
        }
    }
    command.output()
}

/// What `engine --version` printed, without surrounding whitespace.
fn query_version(engine: Engine, path: &Path) -> Result<String, RunRefusal> {
    let output = start(path, &["--version".into()], None)
        .map_err(|cause| RunRefusal::new(path, Reason::VersionNotQueried { engine, cause }))?;
    if !output.status.success() {
        return Err(RunRefusal::new(
            path,
            Reason::VersionQueryFailed {
                engine,
                status: output.status,
            },
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The arguments `engine` gets: its own flags, the module, then the fixed
/// arguments.
fn engine_args(engine: Engine, module: &OsString) -> Vec<OsString> {
    let mut args: Vec<OsString> = engine.run_flags().iter().map(OsString::from).collect();
    args.push(module.clone());
    args.extend(INVOKE_ARGUMENTS.iter().map(OsString::from));
    args
}

/// Run `module` on `engine`, in the staged folder, once the seal is checked.
fn run_engine(
    engine: Engine,
    path: &Path,
    staged: &Staged,
    module: &OsString,
) -> Result<EngineRun, RunRefusal> {
    staged.check_unchanged()?;
    let output = start(path, &engine_args(engine, module), Some(staged.folder()))
        .map_err(|cause| RunRefusal::new(path, Reason::EngineNotStarted { engine, cause }))?;
    Ok(EngineRun {
        engine,
        path: path.to_path_buf(),
        output,
    })
}

/// Both engines must exit successfully, and their stdout must match byte for
/// byte. Two equal failures are still failures.
fn compare(wasmtime: &EngineRun, wasmer: &EngineRun, module: &Path) -> Result<(), RunRefusal> {
    for run in [wasmtime, wasmer] {
        if !run.output.status.success() {
            return Err(RunRefusal::new(
                &run.path,
                Reason::EngineFailed {
                    engine: run.engine,
                    status: run.output.status,
                    stderr: run.output.stderr.clone(),
                },
            ));
        }
    }
    if wasmtime.output.stdout != wasmer.output.stdout {
        return Err(RunRefusal::new(
            module,
            Reason::OutputsDiffer {
                wasmtime: wasmtime.output.stdout.clone(),
                wasmer: wasmer.output.stdout.clone(),
            },
        ));
    }
    Ok(())
}

/// The receipt, in wc-001's `key: value` shape. The lab CID is printed alone
/// on its line: no engine version is ever part of the name.
fn receipt_text(
    cid: LabCid,
    entrypoint: &str,
    wasmtime_version: &str,
    wasmer_version: &str,
    wasmtime: &EngineRun,
    wasmer: &EngineRun,
) -> String {
    let stdout = |run: &EngineRun| format!("{:?}", String::from_utf8_lossy(&run.output.stdout));
    let exit = |run: &EngineRun| run.output.status.code().unwrap_or(-1);
    format!(
        "schema: {RECEIPT_SCHEMA}\n\
         bundle: {cid}\n\
         entrypoint: {entrypoint}\n\
         function: {INVOKE_FUNCTION}\n\
         arguments: {}\n\
         wasmtime_version: {wasmtime_version}\n\
         wasmer_version: {wasmer_version}\n\
         wasmtime_exit: {}\n\
         wasmtime_stdout: {}\n\
         wasmer_exit: {}\n\
         wasmer_stdout: {}\n",
        INVOKE_ARGUMENTS.join(" "),
        exit(wasmtime),
        stdout(wasmtime),
        exit(wasmer),
        stdout(wasmer),
    )
}
