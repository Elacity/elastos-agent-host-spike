//! wc-005a: run one host engine on a verified bundle's entrypoint module, as a
//! library call. There is no command and no binary.
//!
//! [`run_engine`] takes wc-004's [`VerifiedBundle`], which engine, the
//! engine's program path and a work root folder. In order:
//!
//! 1. the engine program path must be absolute, so it can never be looked up
//!    on PATH or resolved against a working folder;
//! 2. the work root must be absolute, byte for byte its own `canonicalize`
//!    result, so no link is anywhere in it, and a folder by its metadata (a
//!    failed metadata read keeps its OS cause);
//! 3. one new folder, named after the engine, is made inside the work root
//!    with mode `0o700`; a name already there is refused, never reused;
//! 4. [`VerifiedBundle::entrypoint`]'s checked bytes, from memory, are written
//!    into it as one new file with the shared [`write_new_file`];
//! 5. the engine is started once, by that same path, as
//!    `run --invoke digest <absolute module path> 1592590337`, with stdin null
//!    and an empty environment. It gets no folder, env or network flag.
//!
//! It returns the engine's stdout. A nonzero exit is refused with the engine,
//! the exit status and its stderr. Every refusal has its own reason and the
//! path it stopped at; nothing is started after a refusal.
//!
//! The runner reads no environment variable and no file, and parses no
//! manifest or module: the verified value already holds the bytes its lab CID
//! names, and the entrypoint the verifier's one manifest read found. Nothing
//! is written outside the new folder.
//!
//! Claim scope. The argv and the empty environment are what this runner
//! controls. With no folder, env or network flag the guest is given no host
//! resource, but the engine itself is a native process with the user's own
//! authority; this runner does not confine it. A host engine opens the module
//! by its path, so a process running as the same user could swap the folder or
//! the file between the write and the engine's open; this runner does not
//! defend against that. Binding launch to verified bytes is the Runtime's
//! launch path, not lab tooling. It is no admission or launch decision.
//!
//! wc-005b: [`run`] is the two-engine runner. It takes a [`RunInput`]: the
//! bundle path, its in-memory name signature, the accepted signer DIDs, both
//! engine program paths and a work root. In order:
//!
//! 1. wc-004's [`verify_bundle`] is called once, with no grants. A refusal is
//!    returned unchanged; nothing is written and no engine is started;
//! 2. [`run_engine`] runs `wasmtime` on the verified value, and returns;
//! 3. only then [`run_engine`] runs `wasmer` on the same value. The two are
//!    separate processes, one after the other, never nested or overlapping;
//! 4. both stdouts must be byte-identical.
//!
//! The first refusal is the answer, as in [`run_engine`]: a refusal of either
//! engine is returned unchanged, with its own path and cause, and `wasmer` is
//! not started after `wasmtime` is refused. So two engines that fail the same
//! way are refused with the first failure's own reason, never as equal
//! outputs. Success returns the verified lab CID and both stdouts.
//!
//! The two-engine result is a behaviour proof on one core module on this
//! machine, not the Component ABI. Both engines are test-only; neither is
//! endorsed.

use crate::bundle::{write_new_file, Reason as WriteReason, RunRefusal as WriteRefusal};
use crate::verify::{verify_bundle, VerifiedBundle, VerifyRefusal};
use capsule_identity::{LabCid, NameSignature};
use std::error::Error;
use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// The export the runner calls: the capsule's one function.
pub const DIGEST_EXPORT: &str = "digest";

/// The argument the runner passes: the capsule's `FIXED_INPUT`, `0x5EED_0001`,
/// in decimal.
pub const DIGEST_ARGUMENT: &str = "1592590337";

/// The file name of the module inside the run folder.
const MODULE_FILE: &str = "module.wasm";

/// The run folder's mode: only its owner may list, enter or write it.
const RUN_DIR_MODE: u32 = 0o700;

/// A test-only host engine. Neither is endorsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Wasmtime,
    Wasmer,
}

impl Engine {
    /// The engine's name, which is also its run folder's name.
    pub fn name(self) -> &'static str {
        match self {
            Engine::Wasmtime => "wasmtime",
            Engine::Wasmer => "wasmer",
        }
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a run was refused. Each step has its own reason.
#[derive(Debug)]
pub enum Reason {
    /// The engine program path is not absolute.
    EngineNotAbsolute,
    /// The work root is not absolute.
    WorkRootNotAbsolute,
    /// The work root could not be resolved (it is missing, or unreadable).
    WorkRootUnresolved(io::Error),
    /// The work root is not its own canonical path: a link, or a `.`, `..`,
    /// doubled or trailing `/` part.
    WorkRootNotCanonical { canonical: PathBuf },
    /// The work root's metadata could not be read after it resolved.
    WorkRootMetadataFailed(io::Error),
    /// The work root is not a folder.
    WorkRootNotAFolder,
    /// Something is already at the run folder's path.
    RunDirExists,
    /// The run folder could not be made.
    RunDirNotCreated(io::Error),
    /// The module file could not be made new.
    ModuleNotCreated(io::Error),
    /// The module file was made, but its bytes could not be written.
    ModuleNotWritten(io::Error),
    /// The shared writer refused for a reason of its own, carried unchanged.
    Writer(WriteReason),
    /// The engine could not be started.
    EngineDidNotStart { engine: Engine, error: io::Error },
    /// The engine ran and exited nonzero, or was stopped by a signal.
    EngineFailed {
        engine: Engine,
        status: ExitStatus,
        stderr: String,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::EngineNotAbsolute => write!(
                f,
                "the engine program path is not absolute: an engine is started only by an absolute path"
            ),
            Reason::WorkRootNotAbsolute => write!(f, "the work root is not an absolute path"),
            Reason::WorkRootUnresolved(error) => {
                write!(f, "the work root cannot be resolved: {error}")
            }
            Reason::WorkRootNotCanonical { canonical } => write!(
                f,
                "the work root is not canonical: it resolves to {}",
                canonical.display()
            ),
            Reason::WorkRootMetadataFailed(error) => {
                write!(f, "the work root's metadata cannot be read: {error}")
            }
            Reason::WorkRootNotAFolder => write!(f, "the work root is not a folder"),
            Reason::RunDirExists => write!(
                f,
                "the run folder already exists: the runner makes a new one and never reuses it"
            ),
            Reason::RunDirNotCreated(error) => {
                write!(f, "the run folder cannot be created: {error}")
            }
            Reason::ModuleNotCreated(error) => {
                write!(f, "the verified entrypoint cannot be created: {error}")
            }
            Reason::ModuleNotWritten(error) => {
                write!(f, "the verified entrypoint cannot be written: {error}")
            }
            Reason::Writer(reason) => write!(f, "the shared writer refused: {reason}"),
            Reason::EngineDidNotStart { engine, error } => {
                write!(f, "{engine} did not start: {error}")
            }
            Reason::EngineFailed {
                engine,
                status,
                stderr,
            } => write!(f, "{engine} failed ({status}): {}", stderr.trim_end()),
        }
    }
}

/// A refused run: the path it stopped at, and why.
#[derive(Debug)]
pub struct Refusal {
    pub path: PathBuf,
    pub reason: Reason,
}

impl Refusal {
    fn new(path: &Path, reason: Reason) -> Refusal {
        Refusal {
            path: path.to_path_buf(),
            reason,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

impl Error for Refusal {}

/// Run `engine`, the program at the absolute path `program`, once on
/// `bundle`'s verified entrypoint bytes, written into a new folder inside
/// `work_root`. The steps and their order are in the module docs; the first
/// refusal is the answer. Success returns the engine's stdout.
pub fn run_engine(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    work_root: &Path,
) -> Result<Vec<u8>, Refusal> {
    if !program.is_absolute() {
        return Err(Refusal::new(program, Reason::EngineNotAbsolute));
    }
    check_work_root(work_root)?;
    let run_dir = work_root.join(engine.name());
    DirBuilder::new()
        .mode(RUN_DIR_MODE)
        .create(&run_dir)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => Refusal::new(&run_dir, Reason::RunDirExists),
            _ => Refusal::new(&run_dir, Reason::RunDirNotCreated(error)),
        })?;
    let module = run_dir.join(MODULE_FILE);
    write_new_file(&module, &bundle.entrypoint().content).map_err(module_refusal)?;
    start_engine(engine, program, &module)
}

/// The work root must be absolute, resolve, be byte for byte its own
/// canonical path, and be a folder by that path's own metadata.
fn check_work_root(work_root: &Path) -> Result<(), Refusal> {
    if !work_root.is_absolute() {
        return Err(Refusal::new(work_root, Reason::WorkRootNotAbsolute));
    }
    let canonical = fs::canonicalize(work_root)
        .map_err(|error| Refusal::new(work_root, Reason::WorkRootUnresolved(error)))?;
    if canonical.as_os_str() != work_root.as_os_str() {
        return Err(Refusal::new(
            work_root,
            Reason::WorkRootNotCanonical { canonical },
        ));
    }
    work_root_folder(work_root, fs::metadata(&canonical))
}

/// The last work-root step, on the canonical path's metadata: a lookup that
/// failed keeps its OS cause; a lookup that worked must show a folder.
pub fn work_root_folder(
    work_root: &Path,
    metadata: io::Result<fs::Metadata>,
) -> Result<(), Refusal> {
    match metadata {
        Err(error) => Err(Refusal::new(
            work_root,
            Reason::WorkRootMetadataFailed(error),
        )),
        Ok(metadata) if !metadata.is_dir() => {
            Err(Refusal::new(work_root, Reason::WorkRootNotAFolder))
        }
        Ok(_) => Ok(()),
    }
}

/// The shared writer's refusal as the runner's own: its path and cause kept,
/// with the runner's words for the module file. A reason the writer has
/// beyond those two is carried unchanged.
pub fn module_refusal(refusal: WriteRefusal) -> Refusal {
    let reason = match refusal.reason {
        WriteReason::ManifestNotCreated(error) => Reason::ModuleNotCreated(error),
        WriteReason::ManifestNotWritten(error) => Reason::ModuleNotWritten(error),
        other => Reason::Writer(other),
    };
    Refusal {
        path: refusal.path,
        reason,
    }
}

/// Start `program` once with the fixed argv, stdin null and an empty
/// environment, and wait for it. A nonzero exit is refused with its stderr.
fn start_engine(engine: Engine, program: &Path, module: &Path) -> Result<Vec<u8>, Refusal> {
    let output = Command::new(program)
        .args(["run", "--invoke", DIGEST_EXPORT])
        .arg(module)
        .arg(DIGEST_ARGUMENT)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Refusal::new(program, Reason::EngineDidNotStart { engine, error }))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(Refusal::new(
            program,
            Reason::EngineFailed {
                engine,
                status: output.status,
                stderr,
            },
        ));
    }
    Ok(output.stdout)
}

/// The two-engine runner's inputs, all explicit: nothing is read from the
/// environment.
#[derive(Clone, Copy, Debug)]
pub struct RunInput<'a> {
    /// The bundle folder to verify.
    pub bundle: &'a Path,
    /// Its in-memory name signature, if any.
    pub signature: Option<&'a NameSignature>,
    /// The accepted signer DIDs.
    pub accepted: &'a [String],
    /// The absolute path of the `wasmtime` program.
    pub wasmtime: &'a Path,
    /// The absolute path of the `wasmer` program.
    pub wasmer: &'a Path,
    /// The work root both run folders are made in.
    pub work_root: &'a Path,
}

/// A two-engine run that passed: the verified lab CID and both stdouts.
///
/// Its fields are private and it has no public constructor, so a value exists
/// only as [`run`] made it. It is no admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoEngineRun {
    cid: LabCid,
    wasmtime: Vec<u8>,
    wasmer: Vec<u8>,
}

impl TwoEngineRun {
    /// The lab CID the verifier checked the signature against.
    pub fn cid(&self) -> LabCid {
        self.cid
    }

    /// What `wasmtime` printed.
    pub fn wasmtime(&self) -> &[u8] {
        &self.wasmtime
    }

    /// What `wasmer` printed.
    pub fn wasmer(&self) -> &[u8] {
        &self.wasmer
    }
}

/// Why a two-engine run was refused. Each reason has its own variant and its
/// own text; the verifier's and the engine runner's refusals are carried
/// unchanged and print exactly as they print them.
#[derive(Debug)]
pub enum TwoEngineRefusal {
    /// The verifier refused the bundle; no engine was started.
    Verify(VerifyRefusal),
    /// [`run_engine`] refused, for either engine.
    Engine(Refusal),
    /// Both engines exited successfully, with different stdouts.
    OutputsDiffer { wasmtime: Vec<u8>, wasmer: Vec<u8> },
}

impl fmt::Display for TwoEngineRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwoEngineRefusal::Verify(refusal) => write!(f, "{refusal}"),
            TwoEngineRefusal::Engine(refusal) => write!(f, "{refusal}"),
            TwoEngineRefusal::OutputsDiffer { wasmtime, wasmer } => write!(
                f,
                "the engines' outputs differ: wasmtime printed {:?}, wasmer printed {:?}",
                String::from_utf8_lossy(wasmtime),
                String::from_utf8_lossy(wasmer)
            ),
        }
    }
}

impl Error for TwoEngineRefusal {}

/// Verify `input.bundle` once, then run it on `wasmtime` and then on
/// `wasmer`, and require byte-identical stdout. The steps and their order are
/// in the module docs; the first refusal is the answer.
pub fn run(input: &RunInput) -> Result<TwoEngineRun, TwoEngineRefusal> {
    let bundle = verify_bundle(input.bundle, input.signature, input.accepted, &[])
        .map_err(TwoEngineRefusal::Verify)?;
    let wasmtime = run_engine(&bundle, Engine::Wasmtime, input.wasmtime, input.work_root)
        .map_err(TwoEngineRefusal::Engine)?;
    let wasmer = run_engine(&bundle, Engine::Wasmer, input.wasmer, input.work_root)
        .map_err(TwoEngineRefusal::Engine)?;
    if wasmtime != wasmer {
        return Err(TwoEngineRefusal::OutputsDiffer { wasmtime, wasmer });
    }
    Ok(TwoEngineRun {
        cid: bundle.cid(),
        wasmtime,
        wasmer,
    })
}
