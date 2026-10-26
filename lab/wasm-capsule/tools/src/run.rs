//! wc-005: verify a bundle, then run the exact verified bytes of its core
//! module under two independent host engines and require the same output.
//!
//! [`run`] does these steps, in order, and stops at the first refusal:
//!
//! 1. wc-004's [`verify_bundle`], with no grants: the one verify path. A
//!    refusal is the verifier's own, and no engine starts.
//! 2. A new OUT_DIR, and inside it a new `staged/` folder holding every entry
//!    of the verified value's `entries()`: the checked bytes, never a re-read
//!    of the bundle.
//! 3. [`crate::bundle_identity`] of the staged copy, compared with the
//!    verified value's `cid()`. A mismatch stops the run before either engine
//!    starts.
//! 4. Each engine's `--version`, recorded as the engine printed it.
//! 5. `wasmtime run --invoke` and then `wasmer run --invoke` of the staged
//!    entrypoint module, with the fixed [`INVOKE_FUNCTION`] and
//!    [`INVOKE_ARGUMENTS`]: two separate processes, one after the other,
//!    neither inside the other, with no directory, environment or network
//!    flag.
//! 6. Both engines must exit successfully, and their stdout must match byte
//!    for byte.
//! 7. A new `OUT_DIR/receipt.txt` records the lab CID, both observed engine
//!    versions, the function, the arguments and both outputs.
//!
//! The engines are inputs ([`Engines`]), never read from the environment, so
//! a test points the runner at a stand-in engine. There is one run path: the
//! input chooses which program starts, not what the runner does.
//!
//! Both engines are test-only host engines; neither is endorsed. The result is
//! a behaviour proof on one core module, never a claim about the Component
//! ABI. The runner makes no admission, launch or publisher-trust decision.
//! It reads no environment variable and parses no manifest or module: the
//! verified value already says which entry is the module.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
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

/// When the runner tells its observer about the staged folder. The observer
/// gets the moment and the staged folder's path and returns nothing, so it
/// cannot steer the run. Tests use it to change the folder at that moment,
/// as another process could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// The staged folder is made; no entry is written yet.
    StagedFolderMade,
    /// Every entry is written; the copy is not named yet.
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
    /// A folder of the staged copy could not be made.
    FolderNotStaged(io::Error),
    /// A verified entry could not be written into the staged copy.
    EntryNotStaged(io::Error),
    /// [`crate::bundle_identity`] refused the staged copy: its own refusal.
    StagedNotNamed(IdentityRefusal),
    /// The staged copy's lab CID is not the verified one.
    StagedNameMismatch { verified: LabCid, staged: LabCid },
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
            Reason::FolderNotStaged(cause) => {
                write!(f, "a staged folder cannot be created: {cause}")
            }
            Reason::EntryNotStaged(cause) => {
                write!(f, "a verified entry cannot be staged: {cause}")
            }
            Reason::StagedNotNamed(refusal) => {
                write!(f, "the staged copy gets no lab CID: {refusal}")
            }
            Reason::StagedNameMismatch { verified, staged } => write!(
                f,
                "the staged copy is named {staged}, not the verified {verified}: no engine started"
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

/// [`run`], telling `observe` about the staged folder at each [`Moment`].
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
    let staged = stage(entries, out_dir, &mut observe)?;
    check_staged_name(&staged, cid)?;
    let module = staged.join(&entrypoint.path);

    let wasmtime_version = query_version(Engine::Wasmtime, engines.wasmtime)?;
    let wasmer_version = query_version(Engine::Wasmer, engines.wasmer)?;
    let wasmtime = run_engine(Engine::Wasmtime, engines.wasmtime, &module)?;
    let wasmer = run_engine(Engine::Wasmer, engines.wasmer, &module)?;
    compare(&wasmtime, &wasmer, &module)?;

    let receipt = out_dir.join(RECEIPT_FILE);
    let text = receipt_text(
        cid,
        &entrypoint.path,
        &wasmtime_version,
        &wasmer_version,
        &wasmtime,
        &wasmer,
    );
    write_new_file(&receipt, text.as_bytes(), Reason::ReceiptNotWritten)?;
    Ok(TwoEngineRun {
        cid,
        stdout: wasmtime.output.stdout,
        wasmtime_version,
        wasmer_version,
        receipt,
    })
}

/// Make the new `out_dir` and its new staged folder, and write every verified
/// entry into it. Returns the staged folder.
fn stage(
    entries: &[BundleEntry],
    out_dir: &Path,
    observe: &mut impl FnMut(Moment, &Path),
) -> Result<PathBuf, RunRefusal> {
    // `create_dir` refuses anything already at OUT_DIR, a link included.
    fs::create_dir(out_dir).map_err(|cause| match cause.kind() {
        io::ErrorKind::AlreadyExists => RunRefusal::new(out_dir, Reason::OutDirExists),
        _ => RunRefusal::new(out_dir, Reason::OutDirNotCreated(cause)),
    })?;
    let staged = out_dir.join(STAGED_DIR);
    fs::create_dir(&staged)
        .map_err(|cause| RunRefusal::new(&staged, Reason::FolderNotStaged(cause)))?;
    observe(Moment::StagedFolderMade, &staged);
    for entry in entries {
        stage_entry(&staged, entry)?;
    }
    observe(Moment::EntriesStaged, &staged);
    Ok(staged)
}

/// Write one verified entry's checked bytes at its path under `staged`,
/// making its folders first. The path comes from cc-capsule-identity's one
/// walk: bundle-relative and `/`-separated.
fn stage_entry(staged: &Path, entry: &BundleEntry) -> Result<(), RunRefusal> {
    let path = staged.join(&entry.path);
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)
            .map_err(|cause| RunRefusal::new(folder, Reason::FolderNotStaged(cause)))?;
    }
    write_new_file(&path, &entry.content, Reason::EntryNotStaged)
}

/// Make the new file `path` and write `bytes` into it. `create_new` refuses
/// any entry already at `path`, a link included. Either failure is `reason`
/// with the system's cause.
fn write_new_file(
    path: &Path,
    bytes: &[u8],
    reason: fn(io::Error) -> Reason,
) -> Result<(), RunRefusal> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|cause| RunRefusal::new(path, reason(cause)))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|cause| RunRefusal::new(path, reason(cause)))
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

/// Start the program at `path` with `args`, by its path, and wait for it. The
/// one place the runner starts a process.
fn start(path: &Path, args: &[OsString]) -> io::Result<Output> {
    Command::new(path_to_run(path))
        .args(args)
        .stdin(Stdio::null())
        .output()
}

/// What `engine --version` printed, without surrounding whitespace.
fn query_version(engine: Engine, path: &Path) -> Result<String, RunRefusal> {
    let output = start(path, &["--version".into()])
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
fn engine_args(engine: Engine, module: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = engine.run_flags().iter().map(OsString::from).collect();
    args.push(module.into());
    args.extend(INVOKE_ARGUMENTS.iter().map(OsString::from));
    args
}

/// Run `module` on `engine`.
fn run_engine(engine: Engine, path: &Path, module: &Path) -> Result<EngineRun, RunRefusal> {
    let output = start(path, &engine_args(engine, module))
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
