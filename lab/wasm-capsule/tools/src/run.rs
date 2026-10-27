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
//!    `run --invoke digest <memory cap> <absolute module path> 1592590337`,
//!    with stdin null and an empty environment. It gets no folder, env or
//!    network flag;
//! 6. task 039: once the engine has exited (its outcome is read first), the
//!    module file, if this run made it, and then the run folder are removed,
//!    on every outcome after step 3: a module write that was refused, an
//!    engine that did not start, failed or succeeded. The folder is removed
//!    with `fs::remove_dir`, never `remove_dir_all`, so an entry someone else
//!    put in it is never deleted; the folder then stays and the removal fails.
//!
//! Which answer wins (task 039): after a success, a failed removal refuses the
//! run with its own reason and the path it stopped at. After a refusal, that
//! first refusal stays the answer, and a failed removal is not reported (a
//! known limit). A runner process that is itself killed leaves its folder (a
//! known limit). A run folder name is still never reused while it exists; a
//! second run in the same work root finds no folder and makes a new one.
//!
//! wc-010b: the memory cap comes from [`VerifiedBundle::memory_mb`], the
//! manifest's declared `resources.memory_mb`, read by the verifier's one
//! manifest read; the runner reads it from no file and no environment. MB is
//! read as 2^20 bytes, so the cap is `memory_mb × 1048576` bytes, in `u64`
//! (no overflow for any `u32`). `wasmtime` gets one argument pair, `-W
//! max-memory-size=<bytes>,max-memories=1,trap-on-grow-failure=y`: the cap is
//! per linear memory, so a module with a second memory, which would get a
//! second cap, is refused at start ("memory count too high"); a `memory.grow`
//! past the cap traps. `wasmer` gets none: its CLI has no memory cap flag (wc-010a), so
//! no cap is claimed for it. The flag is a test-only limit, never an engine
//! choice; the engine choice is Anders's.
//!
//! It returns the engine's exit status and stdout. A nonzero exit is refused
//! with the engine, the exit status and its stderr. Every refusal has its own reason and the
//! path it stopped at; nothing is started after a refusal.
//!
//! Task 038: a start that was given a memory cap argument and exits with the
//! status and first stderr line task 038 measured for a `-W` argument the
//! pinned wasmtime rejects (exit 2, a line that starts `error: ` and holds
//! ` -W `; LOG) is refused as a rejected cap, naming the argument; the module
//! is never run again without its cap. Any other nonzero exit stays a failed
//! run. `run_engine` makes no `--version` query and does not check the
//! version: [`run`], the entry that starts both engines, checks the pins. The
//! runner promises no fuel or time limit, and none other than the memory cap.
//!
//! The runner reads no environment variable and no file, and parses no
//! manifest or module: the verified value already holds the bytes its lab CID
//! names, and the entrypoint the verifier's one manifest read found. Nothing
//! is written outside the new folder, and nothing the runner made is left in
//! the work root after `run_engine` returns, except when removing it failed:
//! that run folder stays (step 6), and after a success the run is refused.
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
//!    with its own reason, engine and cause, and no module run starts.
//!    Task 038: that first line, split on single spaces, must name the engine
//!    as its first word and the pinned version ([`WASMTIME_VERSION`],
//!    [`WASMER_VERSION`]) as its second, exactly; anything after them is
//!    allowed. Another line is refused as soon as it is read, so an unpinned
//!    `wasmtime` is refused before `wasmer` is asked, and no module run
//!    starts on an engine the runner's facts were not measured on;
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
//! versions are what the engines printed, never configured, and none of them
//! is part of the lab CID. Since task 038 an engine upgrade is refused before
//! any module run; changing a pin is a deliberate edit after a fresh probe.
//! wc-010c: success also returns the declared `memory_mb` the module runs were
//! given and, per engine, the memory cap argument it was started with, read
//! back from that process's own argv (the argument after `-W`), never from the
//! engine's name or a constant; the receipt renders these too. `wasmer`'s is
//! none.
//!
//! The two-engine result is a behaviour proof on one core module on this
//! machine, not the Component ABI. Both engines are test-only, not endorsed.
//! The runner gives the engines no host function of its own, so a granted
//! import is only let through verification, not hosted (wc-009b). The grants
//! are a lab stand-in, not admission.

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

/// The bytes in one declared MB: the manifest's `memory_mb` is read as 2^20
/// bytes, as wc-010a's probes read it.
const BYTES_PER_MB: u64 = 1 << 20;

/// The one `wasmtime` version [`run`] starts (task 038). Task 021 (wc-010a)
/// measured `-W max-memory-size=...` on wasmtime 45.0.1, and task 030 measured
/// that it applies a module's own memory maximum; both facts hold for this
/// version only. Change it only by a deliberate edit after a fresh probe like
/// 021 and 030.
pub const WASMTIME_VERSION: &str = "45.0.1";

/// The one `wasmer` version [`run`] starts (task 038). Task 021 (wc-010a) found
/// no memory cap flag in wasmer 7.5.0, and task 030 measured that it applies a
/// module's own memory maximum; both facts hold for this version only. Change
/// it only by a deliberate edit after a fresh probe like 021 and 030.
pub const WASMER_VERSION: &str = "7.5.0";

/// The exit status wasmtime 45.0.1 gave for a `-W` argument it rejected, an
/// unknown key and a bad value alike (LOG, task 038's two probes).
const CAP_REJECTED_STATUS: i32 = 2;

/// How the first stderr line of that refusal starts (LOG, task 038's two
/// probes); a module that fails to load starts `Error: ` instead.
const CAP_REJECTED_PREFIX: &str = "error: ";

/// The text in that line that names the `-W` option (LOG, task 038's two
/// probes).
const CAP_REJECTED_OPTION: &str = " -W ";

/// A host engine: test-only, not endorsed.
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

    /// The one version of the engine [`run`] starts: [`WASMTIME_VERSION`] or
    /// [`WASMER_VERSION`].
    pub fn pinned_version(self) -> &'static str {
        match self {
            Engine::Wasmtime => WASMTIME_VERSION,
            Engine::Wasmer => WASMER_VERSION,
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
    /// The first line the engine's `--version` query printed does not name
    /// the engine's pinned version; no module run starts.
    VersionNotPinned {
        engine: Engine,
        printed: Vec<u8>,
        pinned: &'static str,
    },
    /// The engine was started with a memory cap argument and rejected it; the
    /// module is not run without its cap.
    CapRejected {
        engine: Engine,
        argument: String,
        status: ExitStatus,
        stderr: String,
    },
    /// The engine succeeded, but its module file or its run folder could not
    /// be removed after it exited (task 039).
    RunDirNotRemoved(io::Error),
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
            Reason::VersionNotPinned {
                engine,
                printed,
                pinned,
            } => write!(
                f,
                "{engine} --version printed {:?}, not the pinned version {engine} {pinned}: no module run starts",
                String::from_utf8_lossy(printed)
            ),
            Reason::CapRejected {
                engine,
                argument,
                status,
                stderr,
            } => write!(
                f,
                "{engine} rejected the memory cap argument -W {argument} ({status}): {}; the module is not run without its cap",
                stderr.trim_end()
            ),
            Reason::RunDirNotRemoved(error) => write!(
                f,
                "the run folder cannot be removed after the engine exited: {error}"
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
///
/// wc-010c: also the declared `memory_mb` the run was given, and the memory
/// cap argument the engine was started with: the argument after `-W` in the
/// argv the process got, read back from that argv, or none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub memory_mb: u32,
    pub memory_cap: Option<String>,
}

/// Run `engine`, the program at the absolute path `program`, once on
/// `bundle`'s verified entrypoint bytes, written into a new folder inside
/// `work_root`, which is removed again once the engine has exited. The steps
/// and their order are in the module docs; the first refusal is the answer.
/// Success returns the engine's exit status and stdout.
pub fn run_engine(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    work_root: &Path,
) -> Result<EngineRun, Refusal> {
    check_program(program)?;
    check_work_root(work_root)?;
    let run_dir = make_run_dir(work_root, engine)?;
    let outcome = write_and_start(bundle, engine, program, &run_dir);
    finish_run(&run_dir, outcome)
}

/// Step 3: one new folder, `<work_root>/<engine name>`, with mode `0o700`. A
/// name already there is refused, never reused; nothing is made then, so
/// nothing is removed.
fn make_run_dir(work_root: &Path, engine: Engine) -> Result<PathBuf, Refusal> {
    let run_dir = work_root.join(engine.name());
    DirBuilder::new()
        .mode(RUN_DIR_MODE)
        .create(&run_dir)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => Refusal::new(&run_dir, Reason::RunDirExists),
            _ => Refusal::new(&run_dir, Reason::RunDirNotCreated(error)),
        })?;
    Ok(run_dir)
}

/// Steps 4 and 5, in the run folder step 3 made: write the verified
/// entrypoint as its module file, then start the engine on it once. Every
/// outcome, a refusal too, goes to [`finish_run`].
fn write_and_start(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    run_dir: &Path,
) -> Result<EngineRun, Refusal> {
    let module = run_dir.join(MODULE_FILE);
    write_new_file(&module, &bundle.entrypoint().content).map_err(module_refusal)?;
    start_engine(engine, program, &module, bundle.memory_mb())
}

/// Task 039: after `outcome`, which is read only once the engine has exited
/// (or never started), remove the run folder through [`remove_run_dir`], on
/// every outcome. After a success, a failed removal refuses the run with its
/// path and cause. After a refusal, that first refusal stays the answer, and a
/// failed removal is not reported (a known limit).
fn finish_run(run_dir: &Path, outcome: Result<EngineRun, Refusal>) -> Result<EngineRun, Refusal> {
    let removed = remove_run_dir(run_dir, module_made(&outcome));
    match (outcome, removed) {
        (Ok(run), Ok(())) => Ok(run),
        (Ok(_), Err(refusal)) => Err(refusal),
        (Err(refusal), _) => Err(refusal),
    }
}

/// Whether the module file was made in the run folder: always, unless the
/// shared writer refused to create it. A creation refusal means something
/// else may be at its path, which the runner never deletes.
fn module_made(outcome: &Result<EngineRun, Refusal>) -> bool {
    !matches!(
        outcome,
        Err(Refusal {
            reason: Reason::ModuleNotCreated(_) | Reason::Writer(_),
            ..
        })
    )
}

/// Remove the module file, if this run made it, then the run folder with
/// `fs::remove_dir`, which removes only an empty folder: an entry someone else
/// put there is never deleted, so the folder then stays and the removal is
/// refused. The first removal that fails is the answer, with its path.
fn remove_run_dir(run_dir: &Path, module_made: bool) -> Result<(), Refusal> {
    if module_made {
        let module = run_dir.join(MODULE_FILE);
        fs::remove_file(&module)
            .map_err(|error| Refusal::new(&module, Reason::RunDirNotRemoved(error)))?;
    }
    fs::remove_dir(run_dir).map_err(|error| Refusal::new(run_dir, Reason::RunDirNotRemoved(error)))
}

/// The memory cap, in bytes, for a declared `memory_mb`: `memory_mb ×
/// 1048576` in `u64`, so no `u32` overflows. The one MB to bytes conversion:
/// the cap argument and [`TwoEngineRun::memory_cap_bytes`] both use it.
fn memory_cap_bytes(memory_mb: u32) -> u64 {
    u64::from(memory_mb) * BYTES_PER_MB
}

/// `engine`'s module-run arguments that cap its linear memory at the
/// declared `memory_mb`. `wasmtime`: `-W max-memory-size=<bytes>` with
/// `max-memories=1`, so the cap is the capsule's whole linear memory, not one
/// of several, and `trap-on-grow-failure=y`, so a grow past the cap traps
/// instead of returning -1. `wasmer`: none, since its CLI has no memory cap
/// flag.
fn memory_cap_args(engine: Engine, memory_mb: u32) -> Vec<String> {
    match engine {
        Engine::Wasmtime => vec![
            "-W".to_owned(),
            format!(
                "max-memory-size={},max-memories=1,trap-on-grow-failure=y",
                memory_cap_bytes(memory_mb)
            ),
        ],
        Engine::Wasmer => Vec::new(),
    }
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

/// Start `program` once with the fixed argv and the memory cap for
/// `memory_mb`, stdin null and an empty environment, and wait for it. A
/// nonzero exit is refused with its stderr: as a rejected cap when
/// [`cap_rejected`] says the engine rejected the cap argument it was given
/// (task 038), else as a failed run. The engine is never started again
/// without its cap. The cap argument it returns is read back from the argv
/// the process was started with.
fn start_engine(
    engine: Engine,
    program: &Path,
    module: &Path,
    memory_mb: u32,
) -> Result<EngineRun, Refusal> {
    let mut command = engine_command(program);
    let output = command
        .args(["run", "--invoke", DIGEST_EXPORT])
        .args(memory_cap_args(engine, memory_mb))
        .arg(module)
        .arg(DIGEST_ARGUMENT)
        .output()
        .map_err(|error| Refusal::new(program, Reason::EngineDidNotStart { engine, error }))?;
    if !output.status.success() {
        let status = output.status;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let reason = match memory_cap_given(&command) {
            Some(argument) if cap_rejected(status, &stderr) => Reason::CapRejected {
                engine,
                argument,
                status,
                stderr,
            },
            _ => Reason::EngineFailed {
                engine,
                status,
                stderr,
            },
        };
        return Err(Refusal::new(program, reason));
    }
    Ok(EngineRun {
        status: output.status,
        stdout: output.stdout,
        memory_mb,
        memory_cap: memory_cap_given(&command),
    })
}

/// The memory cap argument `command` was started with: the argument after
/// its `-W`, as passed, or none when its argv has no `-W`. Only
/// [`memory_cap_args`] adds a `-W`.
fn memory_cap_given(command: &Command) -> Option<String> {
    let mut args = command.get_args();
    args.find(|arg| *arg == "-W")?;
    args.next().map(|arg| arg.to_string_lossy().into_owned())
}

/// Whether a start given a memory cap argument failed because the engine
/// rejected that argument: it exited with [`CAP_REJECTED_STATUS`] and its
/// first stderr line starts with [`CAP_REJECTED_PREFIX`] and holds
/// [`CAP_REJECTED_OPTION`], the values task 038 measured on the pinned
/// wasmtime (LOG).
fn cap_rejected(status: ExitStatus, stderr: &str) -> bool {
    let first_line = stderr.lines().next().unwrap_or("");
    status.code() == Some(CAP_REJECTED_STATUS)
        && first_line.starts_with(CAP_REJECTED_PREFIX)
        && first_line.contains(CAP_REJECTED_OPTION)
}

/// Ask `engine`, the program at the absolute path `program`, for its version:
/// one `--version` process through [`engine_command`], the path and rules a
/// module run uses. Its first stdout line is kept as printed, without the
/// newline. A query that does not start, exits nonzero or prints an empty
/// first line is refused with its own reason; so is a first line that
/// [`check_pinned`] refuses, as soon as it is read.
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
    let line = match first_line {
        Some(line) if !line.is_empty() => Ok(line.to_vec()),
        _ => Err(Refusal::new(program, Reason::VersionEmpty { engine })),
    }?;
    check_pinned(engine, program, &line)?;
    Ok(line)
}

/// The pin rule (task 038): `line`, the first line `engine --version`
/// printed, split on single spaces, must have the engine's name as its first
/// word and [`Engine::pinned_version`] as its second, exactly; anything after
/// those two words is allowed. Any other line is refused, so an engine of
/// another version never starts a module run on facts measured on the pinned
/// one.
fn check_pinned(engine: Engine, program: &Path, line: &[u8]) -> Result<(), Refusal> {
    let pinned = engine.pinned_version();
    let mut words = line.split(|&byte| byte == b' ');
    if words.next() == Some(engine.name().as_bytes()) && words.next() == Some(pinned.as_bytes()) {
        return Ok(());
    }
    Err(Refusal::new(
        program,
        Reason::VersionNotPinned {
            engine,
            printed: line.to_vec(),
            pinned,
        },
    ))
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
/// grants; wc-010c: the declared `memory_mb` the module runs were given and
/// each engine's memory cap argument, as its [`EngineRun`] read it back from
/// the argv it was started with.
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
    memory_mb: u32,
    memory_caps: [Option<String>; 2],
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

    /// The declared `memory_mb` the module runs were given: the manifest's
    /// `resources.memory_mb`, from the verifier's one manifest read.
    pub fn memory_mb(&self) -> u32 {
        self.memory_mb
    }

    /// The declared size in bytes, `memory_mb × 1048576`, by the same
    /// conversion that makes `wasmtime`'s cap argument.
    pub fn memory_cap_bytes(&self) -> u64 {
        memory_cap_bytes(self.memory_mb)
    }

    /// The memory cap argument `engine`'s module run was started with (the
    /// argument after its `-W`), or `None` when it was given none.
    pub fn memory_cap(&self, engine: Engine) -> Option<&str> {
        match engine {
            Engine::Wasmtime => self.memory_caps[0].as_deref(),
            Engine::Wasmer => self.memory_caps[1].as_deref(),
        }
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
    let memory_mb = wasmtime.memory_mb;
    let memory_caps = [wasmtime.memory_cap, wasmer.memory_cap];
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
        memory_mb,
        memory_caps,
    })
}
