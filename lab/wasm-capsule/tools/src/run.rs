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
//! It returns the engine's exit status and stdout. A nonzero exit is refused
//! with the engine, the exit status and its stderr. Every refusal has its own reason and the
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
//! bundle path, its in-memory name signature, the accepted signer DIDs, the
//! granted imports (wc-009a: the caller's list from the lab grants file, read
//! by [`crate::verify::read_grants`]), both engine program paths and a work
//! root. In order:
//!
//! 1. wc-004's [`verify_bundle`] is called once, with the granted imports
//!    passed unchanged. A refusal is returned unchanged; nothing is written and
//!    no engine is started, so a module with an import that is not granted
//!    never reaches an engine;
//! 2. wc-005c: each engine is asked `--version`, `wasmtime` and then `wasmer`,
//!    by the same absolute program path a module run starts and with the same
//!    no-ambient rules (one process each, an empty environment, stdin null).
//!    The first line of its stdout is kept as printed. A version query that
//!    does not start, exits nonzero or prints an empty first line is refused
//!    with its own reason, engine and cause, and no module run starts;
//! 3. [`run_engine`] runs `wasmtime` on the verified value, and returns;
//! 4. only then [`run_engine`] runs `wasmer` on the same value. The two are
//!    separate processes, one after the other, never nested or overlapping;
//! 5. both stdouts must be byte-identical.
//!
//! The first refusal is the answer, as in [`run_engine`]: a refusal of either
//! engine is returned unchanged, with its own path and cause, and `wasmer` is
//! not started after `wasmtime` is refused. So two engines that fail the same
//! way are refused with the first failure's own reason, never as equal
//! outputs. Success returns the verified lab CID, both observed versions, both
//! exit statuses and both stdouts, plus the verifier's linked imports and
//! unused grants; [`crate::receipt`] renders the first five. The
//! versions are what the engines printed, never configured, so an engine
//! upgrade shows in the receipt, and none of them is part of the lab CID.
//!
//! The two-engine result is a behaviour proof on one core module on this
//! machine, not the Component ABI. Both engines are test-only; neither is
//! endorsed. The runner gives the engines no host function of its own, so a
//! granted import is only let through verification, not hosted (wc-009b). The
//! grants are a lab stand-in, not admission.

use crate::bundle::{write_new_file, Reason as WriteReason, RunRefusal as WriteRefusal};
use crate::verify::{verify_bundle, DeclaredImport, VerifiedBundle, VerifyRefusal};
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
    /// The engine's `--version` query could not be started.
    VersionDidNotStart { engine: Engine, error: io::Error },
    /// The engine's `--version` query exited nonzero, or was stopped by a
    /// signal.
    VersionFailed {
        engine: Engine,
        status: ExitStatus,
        stderr: String,
    },
    /// The engine's `--version` query exited 0 with an empty first stdout
    /// line.
    VersionEmpty { engine: Engine },
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
            Reason::VersionDidNotStart { engine, error } => {
                write!(f, "{engine} --version did not start: {error}")
            }
            Reason::VersionFailed {
                engine,
                status,
                stderr,
            } => write!(
                f,
                "{engine} --version failed ({status}): {}",
                stderr.trim_end()
            ),
            Reason::VersionEmpty { engine } => write!(
                f,
                "{engine} --version printed no version: its first stdout line is empty"
            ),
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

/// One engine run that exited successfully: its exit status, as the OS
/// reported it, and its stdout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

/// Run `engine`, the program at the absolute path `program`, once on
/// `bundle`'s verified entrypoint bytes, written into a new folder inside
/// `work_root`. The steps and their order are in the module docs; the first
/// refusal is the answer. Success returns the engine's exit status and stdout.
pub fn run_engine(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    work_root: &Path,
) -> Result<EngineRun, Refusal> {
    check_program(program)?;
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

/// An engine is started only by an absolute path, so it is never looked up on
/// PATH or resolved against a working folder. A module run and a version query
/// both check their program here.
fn check_program(program: &Path) -> Result<(), Refusal> {
    if !program.is_absolute() {
        return Err(Refusal::new(program, Reason::EngineNotAbsolute));
    }
    Ok(())
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

/// `program` as a command with no ambient input: an empty environment and
/// stdin null. A module run and a version query both start an engine only
/// through here, each adding its own fixed argv.
fn engine_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear().stdin(Stdio::null());
    command
}

/// Start `program` once with the fixed argv, stdin null and an empty
/// environment, and wait for it. A nonzero exit is refused with its stderr.
fn start_engine(engine: Engine, program: &Path, module: &Path) -> Result<EngineRun, Refusal> {
    let output = engine_command(program)
        .args(["run", "--invoke", DIGEST_EXPORT])
        .arg(module)
        .arg(DIGEST_ARGUMENT)
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
    Ok(EngineRun {
        status: output.status,
        stdout: output.stdout,
    })
}

/// Ask `engine`, the program at the absolute path `program`, for its version:
/// one `--version` process through [`engine_command`], the path and rules a
/// module run uses. Its first stdout line is kept as printed, without the
/// newline. A query that does not start, exits nonzero or prints an empty
/// first line is refused with its own reason.
fn query_version(engine: Engine, program: &Path) -> Result<Vec<u8>, Refusal> {
    check_program(program)?;
    let answer = engine_command(program)
        .arg("--version")
        .output()
        .map_err(|error| Refusal::new(program, Reason::VersionDidNotStart { engine, error }))?;
    if !answer.status.success() {
        let stderr = String::from_utf8_lossy(&answer.stderr).into_owned();
        return Err(Refusal::new(
            program,
            Reason::VersionFailed {
                engine,
                status: answer.status,
                stderr,
            },
        ));
    }
    let first_line = answer.stdout.split(|&byte| byte == b'\n').next();
    match first_line {
        Some(line) if !line.is_empty() => Ok(line.to_vec()),
        _ => Err(Refusal::new(program, Reason::VersionEmpty { engine })),
    }
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
    /// The granted imports, from the lab grants file: a lab stand-in, not
    /// admission.
    pub granted: &'a [DeclaredImport],
    /// The absolute path of the `wasmtime` program.
    pub wasmtime: &'a Path,
    /// The absolute path of the `wasmer` program.
    pub wasmer: &'a Path,
    /// The work root both run folders are made in.
    pub work_root: &'a Path,
}

/// A two-engine run that passed: the verified lab CID, each engine's observed
/// version and exit status, both stdouts, the linked imports and the unused
/// grants.
///
/// Its fields are private and it has no public constructor, so a value exists
/// only as [`run`] made it. It is no admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoEngineRun {
    cid: LabCid,
    wasmtime_version: Vec<u8>,
    wasmer_version: Vec<u8>,
    statuses: [ExitStatus; 2],
    wasmtime: Vec<u8>,
    wasmer: Vec<u8>,
    linked: Vec<DeclaredImport>,
    unused_grants: Vec<DeclaredImport>,
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

    /// What `engine` printed for its module run.
    pub fn stdout(&self, engine: Engine) -> &[u8] {
        match engine {
            Engine::Wasmtime => self.wasmtime(),
            Engine::Wasmer => self.wasmer(),
        }
    }

    /// The first line `engine --version` printed, without its newline.
    pub fn version(&self, engine: Engine) -> &[u8] {
        match engine {
            Engine::Wasmtime => &self.wasmtime_version,
            Engine::Wasmer => &self.wasmer_version,
        }
    }

    /// How `engine`'s module run exited, as the OS reported it.
    pub fn status(&self, engine: Engine) -> ExitStatus {
        match engine {
            Engine::Wasmtime => self.statuses[0],
            Engine::Wasmer => self.statuses[1],
        }
    }

    /// The imports both in the signed module and granted: the verifier's
    /// `imports()`, the audit's own list.
    pub fn linked(&self) -> &[DeclaredImport] {
        &self.linked
    }

    /// The grants the module does not import, in file order: the verifier's
    /// `unused_grants()`.
    pub fn unused_grants(&self) -> &[DeclaredImport] {
        &self.unused_grants
    }
}

/// Why a two-engine run was refused. Each reason has its own variant and its
/// own text; the verifier's and the engine runner's refusals are carried
/// unchanged and print exactly as they print them.
#[derive(Debug)]
pub enum TwoEngineRefusal {
    /// The verifier refused the bundle; no engine was started.
    Verify(VerifyRefusal),
    /// An engine's `--version` query was refused; no module run started.
    Version(Refusal),
    /// [`run_engine`] refused, for either engine.
    Engine(Refusal),
    /// Both engines exited successfully, with different stdouts.
    OutputsDiffer { wasmtime: Vec<u8>, wasmer: Vec<u8> },
}

impl fmt::Display for TwoEngineRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwoEngineRefusal::Verify(refusal) => write!(f, "{refusal}"),
            TwoEngineRefusal::Version(refusal) => write!(f, "{refusal}"),
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

/// Verify `input.bundle` once, ask both engines their version, then run it on
/// `wasmtime` and then on `wasmer`, and require byte-identical stdout. The
/// steps and their order are in the module docs; the first refusal is the
/// answer.
pub fn run(input: &RunInput) -> Result<TwoEngineRun, TwoEngineRefusal> {
    let bundle = verify_bundle(input.bundle, input.signature, input.accepted, input.granted)
        .map_err(TwoEngineRefusal::Verify)?;
    let wasmtime_version =
        query_version(Engine::Wasmtime, input.wasmtime).map_err(TwoEngineRefusal::Version)?;
    let wasmer_version =
        query_version(Engine::Wasmer, input.wasmer).map_err(TwoEngineRefusal::Version)?;
    let wasmtime = run_engine(&bundle, Engine::Wasmtime, input.wasmtime, input.work_root)
        .map_err(TwoEngineRefusal::Engine)?;
    let wasmer = run_engine(&bundle, Engine::Wasmer, input.wasmer, input.work_root)
        .map_err(TwoEngineRefusal::Engine)?;
    let statuses = [wasmtime.status, wasmer.status];
    let (wasmtime, wasmer) = (wasmtime.stdout, wasmer.stdout);
    if wasmtime != wasmer {
        return Err(TwoEngineRefusal::OutputsDiffer { wasmtime, wasmer });
    }
    Ok(TwoEngineRun {
        cid: bundle.cid(),
        wasmtime_version,
        wasmer_version,
        statuses,
        wasmtime,
        wasmer,
        linked: bundle.imports().to_vec(),
        unused_grants: bundle.unused_grants().to_vec(),
    })
}
