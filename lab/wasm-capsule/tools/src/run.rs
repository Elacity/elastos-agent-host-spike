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
//!    network flag. Task 043: the runner waits for it at most the run budget
//!    (below), applied from outside the engine;
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
//! past the cap traps. `wasmer` gets none: its CLI has no memory cap flag
//! (wc-010a). The flag is a test-only limit, never an engine choice; the
//! engine choice is Anders's.
//!
//! Task 033 (M1 C0 lab half): the cap every engine applies is the module's own
//! memory maximum (task 030: wasmtime 45.0.1 and wasmer 7.5.0 both apply it
//! with no flag). So right after the zero-budget check, before the program
//! and work root are checked or anything is made, [`run_engine`] checks the verified
//! entrypoint's memory limits, read only through
//! `wasm_capsule_audit::memories`, the lab's one module reader; [`run`] calls
//! the same check once, right after verification. A module with no memory
//! passes. One with more than one memory, a memory with no maximum, or a
//! maximum above the declared `memory_mb` is refused, each with its own
//! reason, before any engine process starts: a module is never run uncapped,
//! and there is no fallback. On a grow past the maximum, wasmer returns -1;
//! wasmtime traps, because of the `trap-on-grow-failure=y` it is given.
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
//! version: [`run`], the entry that starts both engines, checks the pins.
//!
//! Task 043 (M1 A7 lab half): every module run has a wall-clock budget, the
//! caller's explicit [`RunControl`]; there is no default, and none is read from
//! the environment or a file. A zero budget is refused before anything is made
//! or started. The budget counts from just after the engine is started. The
//! runner reads the engine's stdout and stderr on a thread each, so a full pipe
//! never blocks it, and polls `try_wait` every [`WAIT_POLL`]. An engine still
//! running when the budget has passed is sent SIGKILL by the runner, reaped,
//! its run folder removed (step 6) and the run refused as `BudgetExceeded`;
//! what it printed is dropped. The budget is applied by the runner alone:
//! nothing is given to the engine or the guest (no fuel or timeout flag, the
//! argv is unchanged), so the guest can neither see nor change it. It is
//! wall-clock time, not CPU time, and each module run gets its own. The
//! `--version` queries have no budget. A runner process that is itself killed
//! leaves its engine running (as it leaves its folder). No fuel limit is
//! promised, and no limit other than this budget and the memory cap.
//!
//! Task 045 (M1 A10 lab half): the caller can cancel a run through a
//! [`CancelHandle`] from its [`RunControl`]: in-memory, thread-safe, no
//! command and no OS signal handler (C2 (c)). [`run_engine`] checks it right
//! after the zero-budget check, before anything is made or started, and the
//! wait loop checks it on every poll, before the exit status and the budget.
//! A cancel seen there stops the engine with SIGKILL, reaps it, drops its
//! output, removes its run folder (step 6, [`finish_run`]) and refuses the run
//! as `Cancelled`, never as `BudgetExceeded` or `EngineFailed`. [`run`] also
//! checks it before each `--version` query, so after a cancel no engine
//! process starts. Limits: a `--version` query is not interrupted mid-query,
//! the verifier is not cancelled mid-call, and a runner process that is itself
//! killed leaves its engine and folder.
//!
//! The runner reads no environment variable and no file, and parses no
//! manifest or module of its own: the verified value already holds the bytes
//! its lab CID names, and the entrypoint the verifier's one manifest read
//! found; its memory limits are read only by `wasm_capsule_audit::memories`
//! (task 033). Nothing
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
//! by [`crate::verify::read_grants`]), both engine program paths, a work root
//! and (task 043) the run control both module runs get. In order:
//!
//! 0. task 043: a zero run budget is refused, before anything else;
//! 1. wc-004's [`verify_bundle`] is called once, with the granted imports
//!    passed unchanged. A refusal is returned unchanged; nothing is written and
//!    no engine is started, so a module with an import that is not granted
//!    never reaches an engine; task 033: then the verified module's memory
//!    check, the one [`run_engine`] calls; a refusal is returned as
//!    [`TwoEngineRefusal::Memory`], and no engine process starts, not even a
//!    `--version` query;
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
//! none. Task 034: and, per engine, the module memory maximum that engine's
//! own [`run_engine`] call was checked against, from its one memory check
//! (none for a module with no memory); the receipt renders it in bytes.
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
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use wasm_capsule_audit::{memories, Refusal as AuditRefusal};

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

/// The bytes in one Wasm page, the unit of a memory's limits: 64 KiB.
const WASM_PAGE_BYTES: u64 = 1 << 16;

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

/// How often the runner asks a running engine whether it has exited (task
/// 043). A run that passed its budget is stopped at most this much later.
pub const WAIT_POLL: Duration = Duration::from_millis(10);

/// Task 043: the caller's explicit control over a module run: its wall-clock
/// budget. There is no default; the runner reads none from the environment or
/// a file. Each module run gets the whole budget, counted from its own start.
///
/// Task 045: and its cancel flag, set only through a [`CancelHandle`] from
/// [`RunControl::cancel_handle`]. A clone shares the flag. The runner reads no
/// signal, environment variable or file for it.
#[derive(Clone, Debug)]
pub struct RunControl {
    budget: Duration,
    cancel: Arc<AtomicBool>,
}

impl RunControl {
    /// A control with a wall-clock `budget` per module run, not cancelled. A
    /// zero budget is made, but refused by [`run_engine`] and [`run`] before
    /// any start.
    pub fn new(budget: Duration) -> RunControl {
        RunControl {
            budget,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The wall-clock budget of one module run.
    pub fn budget(&self) -> Duration {
        self.budget
    }

    /// Task 045: a handle that cancels every run given this control (or a
    /// clone of it), from any thread.
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            cancel: Arc::clone(&self.cancel),
        }
    }

    /// Task 045: whether a [`CancelHandle`] of this control has cancelled it.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

/// Task 045 (M1 A10 lab half): the caller's cancel signal, in library form.
/// There is no command and no OS signal handler (C2 (c)); a future command's
/// signal handler, or a test thread, calls [`CancelHandle::cancel`]. Once
/// cancelled, a control stays cancelled.
#[derive(Clone, Debug)]
pub struct CancelHandle {
    cancel: Arc<AtomicBool>,
}

impl CancelHandle {
    /// Cancel the runs given this handle's [`RunControl`]: no engine starts
    /// after it, and a running one is stopped with SIGKILL, reaped, and its run
    /// folder removed; the run is refused as `Cancelled`.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

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
    /// The run control's budget is zero; nothing was made or started (task
    /// 043).
    BudgetZero,
    /// The engine still ran when its budget had passed; the runner stopped it
    /// with SIGKILL and reaped it (task 043).
    BudgetExceeded { engine: Engine, budget: Duration },
    /// The runner could not send SIGKILL to an engine it was stopping (task
    /// 043).
    EngineNotStopped { engine: Engine, error: io::Error },
    /// The runner could not learn whether the engine had exited, or could not
    /// reap it (task 043).
    EngineNotWaited { engine: Engine, error: io::Error },
    /// The engine's stdout or stderr could not be read (task 043).
    OutputNotRead { engine: Engine, error: io::Error },
    /// `wasm_capsule_audit::memories` refused the entrypoint module, its
    /// refusal carried unchanged; no engine is started (task 033).
    MemoryNotRead(AuditRefusal),
    /// The entrypoint module has more than one memory, imported or defined;
    /// the declared size caps one linear memory, so no engine is started (task
    /// 033).
    MemoryCountAboveOne { count: usize },
    /// The entrypoint module's memory declares no maximum, so no engine
    /// applies the declared size to it; it is not run uncapped (task 033).
    MemoryMaximumMissing { minimum: u64 },
    /// The entrypoint module's memory maximum, in pages, is above the declared
    /// `memory_mb`; it is not run uncapped (task 033).
    MemoryMaximumAboveDeclared { maximum: u64, memory_mb: u32 },
    /// The caller cancelled the run (task 045): before `engine` was started,
    /// so nothing was made or started, or while it ran, so the runner stopped
    /// it with SIGKILL, reaped it and removed its run folder.
    Cancelled { engine: Engine },
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
            Reason::BudgetZero => write!(f, "the run budget is zero: no engine is started"),
            Reason::BudgetExceeded { engine, budget } => write!(
                f,
                "{engine} still ran at its run budget of {} ms: the runner stopped it with SIGKILL",
                budget.as_millis()
            ),
            Reason::EngineNotStopped { engine, error } => {
                write!(f, "the runner could not stop {engine} with SIGKILL: {error}")
            }
            Reason::EngineNotWaited { engine, error } => {
                write!(f, "the runner could not wait for {engine}: {error}")
            }
            Reason::OutputNotRead { engine, error } => {
                write!(f, "{engine}'s output could not be read: {error}")
            }
            Reason::MemoryNotRead(refusal) => write!(
                f,
                "the module's memory limits cannot be read: {refusal}; no engine is started"
            ),
            Reason::MemoryCountAboveOne { count } => write!(
                f,
                "the module has {count} memories: the declared size caps one linear memory, so the module is not run uncapped"
            ),
            Reason::MemoryMaximumMissing { minimum } => write!(
                f,
                "the module's memory (minimum {minimum} × 64 KiB) declares no maximum: the module is not run uncapped"
            ),
            Reason::MemoryMaximumAboveDeclared { maximum, memory_mb } => write!(
                f,
                "the module's memory maximum, {maximum} × 64 KiB, is above the declared {memory_mb} MB ({} × 64 KiB): the module is not run uncapped",
                memory_cap_bytes(*memory_mb) / WASM_PAGE_BYTES
            ),
            Reason::Cancelled { engine } => write!(
                f,
                "the run on {engine} was cancelled by its caller: no engine starts after a cancel, and a running one is stopped with SIGKILL"
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
///
/// Task 034: also the module memory maximum, in pages, that this run was
/// checked against: the value [`check_module_memory`] returned in this
/// [`run_engine`] call, or none for a module with no memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub memory_mb: u32,
    pub memory_cap: Option<String>,
    pub memory_maximum: Option<u64>,
}

/// Run `engine`, the program at the absolute path `program`, once on
/// `bundle`'s verified entrypoint bytes, written into a new folder inside
/// `work_root`, which is removed again once the engine has exited. Task 043:
/// the engine runs at most `control`'s budget; a zero budget is refused first.
/// Task 045: then a cancelled `control` is refused ([`check_cancel`]), and a
/// cancel while the engine runs stops it. Task 033: then the module's memory is
/// checked ([`check_module_memory`]), before any folder is made.
/// The steps and their order are in the module docs; the first refusal is the
/// answer. Success returns the engine's exit status and stdout, and (task 034)
/// the maximum that check returned.
pub fn run_engine(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    work_root: &Path,
    control: &RunControl,
) -> Result<EngineRun, Refusal> {
    check_budget(control, work_root)?;
    check_cancel(control, engine, program)?;
    let memory_maximum = check_module_memory(bundle)?;
    check_program(program)?;
    check_work_root(work_root)?;
    let run_dir = make_run_dir(work_root, engine)?;
    let outcome = write_and_start(bundle, engine, program, &run_dir, control);
    finish_run(&run_dir, outcome).map(|run| EngineRun {
        memory_maximum,
        ..run
    })
}

/// Task 043: a zero budget is refused, with `work_root` as its path, before
/// any folder is made or any engine started: no engine can run inside it.
/// [`run_engine`] and [`run`] both check it here.
fn check_budget(control: &RunControl, work_root: &Path) -> Result<(), Refusal> {
    if control.budget().is_zero() {
        return Err(Refusal::new(work_root, Reason::BudgetZero));
    }
    Ok(())
}

/// Task 045: a cancelled `control` is refused as `Cancelled` for `engine`, with
/// `program` as its path, before that engine is started: [`run_engine`] checks
/// here before anything is made, and [`run`] before each `--version` query.
fn check_cancel(control: &RunControl, engine: Engine, program: &Path) -> Result<(), Refusal> {
    if control.is_cancelled() {
        return Err(Refusal::new(program, Reason::Cancelled { engine }));
    }
    Ok(())
}

/// Task 033 (M1 C0 lab half): the one memory check. The entrypoint module's
/// memory limits are read only through `wasm_capsule_audit::memories`, the
/// lab's one module reader, on the verified bytes; a refusal of that reader is
/// carried unchanged. A module with no memory passes, with none: it has no
/// linear memory to grow. More than one memory is refused; so is a memory with
/// no maximum, and one whose maximum in bytes (pages × 65536, in `u64`,
/// saturating) is above [`memory_cap_bytes`] of the declared `memory_mb`. Each
/// refusal has the entrypoint's path in the bundle and its own reason, and
/// nothing is made or started, so a module is never run uncapped. Success
/// returns the checked maximum in pages. [`run_engine`] and [`run`] both check
/// here, before any engine process starts.
fn check_module_memory(bundle: &VerifiedBundle) -> Result<Option<u64>, Refusal> {
    let module = bundle.entrypoint();
    let refuse = |reason| Refusal::new(Path::new(&module.path), reason);
    let limits =
        memories(&module.content).map_err(|refusal| refuse(Reason::MemoryNotRead(refusal)))?;
    let memory = match limits.as_slice() {
        [] => return Ok(None),
        [memory] => memory,
        _ => {
            let count = limits.len();
            return Err(refuse(Reason::MemoryCountAboveOne { count }));
        }
    };
    let minimum = memory.minimum;
    let maximum = memory
        .maximum
        .ok_or_else(|| refuse(Reason::MemoryMaximumMissing { minimum }))?;
    let memory_mb = bundle.memory_mb();
    if page_bytes(maximum) > memory_cap_bytes(memory_mb) {
        return Err(refuse(Reason::MemoryMaximumAboveDeclared {
            maximum,
            memory_mb,
        }));
    }
    Ok(Some(maximum))
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
/// entrypoint as its module file, then start the engine on it once, within
/// `control`'s budget. Every outcome, a refusal too, goes to [`finish_run`].
fn write_and_start(
    bundle: &VerifiedBundle,
    engine: Engine,
    program: &Path,
    run_dir: &Path,
    control: &RunControl,
) -> Result<EngineRun, Refusal> {
    let module = run_dir.join(MODULE_FILE);
    write_new_file(&module, &bundle.entrypoint().content).map_err(module_refusal)?;
    // Task 043: `control` bound into the one start, so the call below, which
    // falsifiers.json entries anchor, keeps its four arguments.
    let start_engine = |engine, program, module: &Path, memory_mb| {
        start_engine(engine, program, module, memory_mb, control)
    };
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

/// The bytes in `pages` Wasm pages: `pages × 65536`, in `u64`, saturating. The
/// one page to bytes conversion: the memory check and
/// [`TwoEngineRun::memory_maximum_bytes`] both use it (task 034).
fn page_bytes(pages: u64) -> u64 {
    pages.saturating_mul(WASM_PAGE_BYTES)
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
/// `memory_mb`, stdin null and an empty environment, and wait for it within
/// `control`'s budget ([`wait_within_budget`], task 043). A nonzero exit is
/// refused with its stderr: as a rejected cap when [`cap_rejected`] says the
/// engine rejected the cap argument it was given (task 038), else as a failed
/// run. The engine is never started again without its cap. The cap argument
/// it returns is read back from the argv the process was started with.
fn start_engine(
    engine: Engine,
    program: &Path,
    module: &Path,
    memory_mb: u32,
    control: &RunControl,
) -> Result<EngineRun, Refusal> {
    let mut command = engine_command(program);
    let child = command
        .args(["run", "--invoke", DIGEST_EXPORT])
        .args(memory_cap_args(engine, memory_mb))
        .arg(module)
        .arg(DIGEST_ARGUMENT)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Refusal::new(program, Reason::EngineDidNotStart { engine, error }))?;
    let output = wait_within_budget(engine, program, child, control)?;
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
        // Task 034: `run_engine` sets it from its one memory check.
        memory_maximum: None,
    })
}

/// Task 043: wait for `child`, the engine [`start_engine`] has just started,
/// until it exits or `control`'s budget, counted from this call, has passed.
/// Its stdout and stderr are each read on a thread of their own, so a full
/// pipe never blocks it, and `try_wait` is asked every [`WAIT_POLL`]. An
/// engine that exits in time gives its output, as `Command::output` would.
/// One still running at the budget is stopped ([`stop_engine`]), both readers
/// are joined, its output is dropped, and the run is refused as
/// `BudgetExceeded`. The runner gives the engine nothing: the budget is never
/// in its argv. A failed `try_wait` stops the engine too, and is refused with
/// its OS cause; so is a failed read of either pipe.
///
/// Task 045: each poll first asks whether `control` was cancelled. If so, the
/// engine is stopped the same way, its output dropped, and the run refused as
/// `Cancelled`, before its exit status or the budget is looked at, so a cancel
/// is never reported as `BudgetExceeded` or `EngineFailed`. [`finish_run`]
/// then removes the run folder, as after every outcome.
fn wait_within_budget(
    engine: Engine,
    program: &Path,
    mut child: Child,
    control: &RunControl,
) -> Result<Output, Refusal> {
    let started = Instant::now();
    let stdout = read_pipe(child.stdout.take());
    let stderr = read_pipe(child.stderr.take());
    let status = loop {
        if control.is_cancelled() {
            stop_engine(engine, program, &mut child)?;
            let _dropped = (joined(stdout), joined(stderr));
            return Err(Refusal::new(program, Reason::Cancelled { engine }));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= control.budget() => {
                stop_engine(engine, program, &mut child)?;
                let _dropped = (joined(stdout), joined(stderr));
                let budget = control.budget();
                return Err(Refusal::new(
                    program,
                    Reason::BudgetExceeded { engine, budget },
                ));
            }
            Ok(None) => thread::sleep(WAIT_POLL),
            Err(error) => {
                stop_engine(engine, program, &mut child)?;
                let _dropped = (joined(stdout), joined(stderr));
                return Err(Refusal::new(
                    program,
                    Reason::EngineNotWaited { engine, error },
                ));
            }
        }
    };
    let output = joined(stdout).and_then(|stdout| Ok((stdout, joined(stderr)?)));
    let (stdout, stderr) =
        output.map_err(|error| Refusal::new(program, Reason::OutputNotRead { engine, error }))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Task 043: stop an engine the runner gives up on: SIGKILL (`Child::kill`),
/// then reap it (`Child::wait`). Neither failure is ignored: a failed kill is
/// refused with its own reason and OS cause, and the engine is then neither
/// waited for nor its pipes read to their end, since it may still run.
fn stop_engine(engine: Engine, program: &Path, child: &mut Child) -> Result<(), Refusal> {
    child
        .kill()
        .map_err(|error| Refusal::new(program, Reason::EngineNotStopped { engine, error }))?;
    child
        .wait()
        .map_err(|error| Refusal::new(program, Reason::EngineNotWaited { engine, error }))?;
    Ok(())
}

/// A thread reading one engine pipe to its end (task 043).
type PipeReader = JoinHandle<io::Result<Vec<u8>>>;

/// Task 043: read `pipe` to its end on a thread of its own. A missing pipe or
/// a reader thread that could not start is an error, never an empty output.
fn read_pipe(pipe: Option<impl Read + Send + 'static>) -> io::Result<PipeReader> {
    let mut pipe = pipe.ok_or_else(|| io::Error::other("the engine's pipe was not made"))?;
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        io::copy(&mut pipe, &mut bytes)?;
        Ok(bytes)
    })
}

/// What a [`read_pipe`] reader read, once its thread has ended; a reader that
/// did not start, failed or panicked is an error.
fn joined(reader: io::Result<PipeReader>) -> io::Result<Vec<u8>> {
    reader?
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("the reader thread panicked")))
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
    /// Task 043: the control each module run gets: each its own budget,
    /// `wasmtime`'s and then `wasmer`'s, never one shared clock.
    pub control: &'a RunControl,
}

/// A two-engine run that passed: the verified lab CID, each engine's observed
/// version and exit status, both stdouts, the linked imports and the unused
/// grants; wc-010c: the declared `memory_mb` the module runs were given and
/// each engine's memory cap argument, as its [`EngineRun`] read it back from
/// the argv it was started with; task 034: each engine's module memory
/// maximum, as its own [`run_engine`] call's memory check returned it.
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
    memory_maximums: [Option<u64>; 2],
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

    /// Task 034: the module memory maximum `engine`'s module run was checked
    /// against, in bytes (pages × 65536, by the memory check's own
    /// conversion), or `None` when the module has no memory. It is the value
    /// that engine's own [`run_engine`] call recorded from its one memory
    /// check, never the declared size or a constant.
    pub fn memory_maximum_bytes(&self, engine: Engine) -> Option<u64> {
        let pages = match engine {
            Engine::Wasmtime => self.memory_maximums[0],
            Engine::Wasmer => self.memory_maximums[1],
        };
        pages.map(page_bytes)
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
    /// Task 033: the entrypoint module's memory limits were refused by the one
    /// memory check; no engine process started, not even a `--version` query.
    Memory(Refusal),
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
            TwoEngineRefusal::Memory(refusal) => write!(f, "{refusal}"),
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
/// answer. Task 043: a zero budget in `input.control` is refused first, as
/// [`run_engine`] refuses it, before any `--version` query. Task 033: the
/// verified module's memory is checked by the same [`check_module_memory`]
/// [`run_engine`] calls, right after verification and before any `--version`
/// query. Task 045: a cancelled `input.control` is refused before each
/// `--version` query (as [`TwoEngineRefusal::Version`], the step it stopped
/// before) and before each module run (as [`TwoEngineRefusal::Engine`]), and a
/// cancel during a module run stops that engine; no engine starts after it.
pub fn run(input: &RunInput) -> Result<TwoEngineRun, TwoEngineRefusal> {
    check_budget(input.control, input.work_root).map_err(TwoEngineRefusal::Engine)?;
    // Task 043: both module runs get `input.control`, each counting its own
    // budget from its own start. Bound here, so the two calls below, which
    // falsifiers.json entries anchor, keep their four arguments.
    let run_engine = |bundle: &VerifiedBundle, engine, program: &Path, work_root: &Path| {
        run_engine(bundle, engine, program, work_root, input.control)
    };
    // Task 045: a cancel is checked before each `--version` query too (and
    // before each module run, inside `run_engine`), so no engine process
    // starts after it. Bound here, so the two anchored query lines below keep
    // their form.
    let query_version = |engine, program: &Path| {
        check_cancel(input.control, engine, program)?;
        query_version(engine, program)
    };
    let bundle = verify_bundle(input.bundle, input.signature, input.accepted, input.granted)
        .map_err(TwoEngineRefusal::Verify)?;
    check_module_memory(&bundle).map_err(TwoEngineRefusal::Memory)?;
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
    let memory_maximums = [wasmtime.memory_maximum, wasmer.memory_maximum];
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
        memory_maximums,
    })
}
