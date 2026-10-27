//! wc-005c: the receipt of a two-engine run, as lab text.
//!
//! [`render`] turns a [`TwoEngineRun`], which only [`crate::run::run`] makes,
//! into `key: value` lines in the shape of wc-001's build receipt
//! (`tools/build`), under its own schema line:
//!
//! ```text
//! schema: wc-005.run-receipt/v3
//! bundle: <the verified lab CID, as its Display form>
//! function: digest
//! argument: 1592590337
//! wasmtime_version: "<the first line wasmtime --version printed>"
//! wasmtime_status: <the module run's exit status>
//! wasmtime_stdout: "<what the module run printed>"
//! wasmer_version: "..."
//! wasmer_status: ...
//! wasmer_stdout: "..."
//! memory_mb: <the declared resources.memory_mb>
//! memory_cap_bytes: <memory_mb × 1048576>
//! wasmtime_memory_cap: ENFORCED max-memory-size=<bytes>,max-memories=1,trap-on-grow-failure=y
//! wasmer_memory_cap: SKIPPED: no memory cap flag in wasmer run --help or wasmer --help (wc-010a)
//! wasmtime_memory_maximum_bytes: <pages × 65536, or none (the module has no memory)>
//! wasmer_memory_maximum_bytes: <pages × 65536, or none (the module has no memory)>
//! ```
//!
//! wc-010c (v2 adds the last four lines): the declared size the module runs
//! were given, in MB and in bytes, then per engine `ENFORCED` with the exact
//! cap argument that engine's run was started with, read back from its argv,
//! or `SKIPPED` with wc-010a's reason when it was started with none. The
//! per-engine line follows the recorded argument only, never the engine's
//! name. No peak memory is recorded (wc-010a: `/usr/bin/time -l` gives the
//! engine process's resident memory, not the capsule's linear memory).
//!
//! Task 034 (v3 adds the last two lines): per engine, `wasmtime` then
//! `wasmer`, the module memory maximum that engine's run was checked against,
//! in bytes: the value [`crate::run::run_engine`]'s one memory check
//! (`wasm_capsule_audit::memories`) returned in that engine's own run, never
//! the declared size, a constant or the engine's name; or `none (the module
//! has no memory)` when it returned none. The `wasmer_memory_cap: SKIPPED`
//! line still reports only that wasmer was given no cap flag.
//!
//! Every value comes from the run: the lab CID the verifier checked, the
//! function and argument the runner passed, and what each engine printed and
//! how it exited. The versions are observed, never configured, so an engine
//! upgrade shows here. They sit beside the lab CID and are no part of it
//! (P15: the hash names the content; versions are provenance). Quoted values
//! are the printed bytes with `escape_ascii`, so every byte is kept and a
//! value cannot add a line.
//!
//! [`write_receipt`] writes it to a caller-given path through the shared
//! [`write_new_file`], so an existing file or a link there is refused with
//! that function's own reason and cause, unchanged. The receipt is not signed;
//! it makes no admission or launch decision.
//!
//! Task 044 (M1 A7 lab half): a refused run gets a receipt too. [`render_refused`]
//! turns the [`TwoEngineRefusal`] that [`crate::run::run`] returned into these
//! lines, in this order:
//!
//! ```text
//! schema: wc-005.run-refusal/v1
//! outcome: <refused|cancelled>
//! reason: <the refusal's id, from refusal_reason>
//! engine: <wasmtime|wasmer|none>
//! detail: "<the refusal's Display>"
//! ```
//!
//! Task 045: `outcome` is `cancelled` for a run the caller cancelled (reason
//! id `cancelled`, [`Reason::Cancelled`]) and `refused` for every other
//! refusal; it is read from the reason id alone.
//!
//! [`refusal_reason`] gives one stable lowercase snake_case id per refusal
//! kind, from one exhaustive `match` over every [`TwoEngineRefusal`] variant
//! and every [`Reason`] variant, with no wildcard arm, so a new variant without
//! an id does not build. A verifier refusal has the one id `verify_refused`;
//! its detail carries the verifier's own text. `engine` is the engine the
//! reason names, else `none`. Every value comes from the refusal; nothing is
//! configured. There is no lab CID line, since a verifier refusal may have
//! none. `detail` is the refusal's Display through `escape_ascii`, as the
//! quoted values above. [`write_refused_receipt`] writes it through the same
//! [`write_new_file`]. It is not signed and makes no admission decision.

use crate::bundle::{write_new_file, RunRefusal};
use crate::run::{Engine, Reason, TwoEngineRefusal, TwoEngineRun, DIGEST_ARGUMENT, DIGEST_EXPORT};
use std::path::Path;

/// The receipt's schema line value.
pub const RECEIPT_SCHEMA: &str = "wc-005.run-receipt/v3";

/// The refusal receipt's schema line value (task 044).
pub const REFUSAL_SCHEMA: &str = "wc-005.run-refusal/v1";

/// The receipt of `run`, as text. The lines and their order are in the module
/// docs.
pub fn render(run: &TwoEngineRun) -> String {
    let mut receipt = format!(
        "schema: {RECEIPT_SCHEMA}\nbundle: {}\nfunction: {DIGEST_EXPORT}\nargument: {DIGEST_ARGUMENT}\n",
        run.cid()
    );
    for engine in [Engine::Wasmtime, Engine::Wasmer] {
        receipt.push_str(&format!(
            "{engine}_version: \"{}\"\n{engine}_status: {}\n{engine}_stdout: \"{}\"\n",
            run.version(engine).escape_ascii(),
            run.status(engine),
            run.stdout(engine).escape_ascii()
        ));
    }
    receipt.push_str(&format!(
        "memory_mb: {}\nmemory_cap_bytes: {}\n",
        run.memory_mb(),
        run.memory_cap_bytes()
    ));
    for engine in [Engine::Wasmtime, Engine::Wasmer] {
        receipt.push_str(&memory_cap_line(engine, run.memory_cap(engine)));
    }
    for engine in [Engine::Wasmtime, Engine::Wasmer] {
        receipt.push_str(&memory_maximum_line(
            engine,
            run.memory_maximum_bytes(engine),
        ));
    }
    receipt
}

/// `engine`'s memory cap line: `ENFORCED` with the cap argument its run was
/// started with, exactly as recorded, or `SKIPPED` with wc-010a's reason when
/// it was started with none.
fn memory_cap_line(engine: Engine, cap: Option<&str>) -> String {
    match cap {
        Some(argument) => format!("{engine}_memory_cap: ENFORCED {argument}\n"),
        None => format!(
            "{engine}_memory_cap: SKIPPED: no memory cap flag in {engine} run --help or {engine} --help (wc-010a)\n"
        ),
    }
}

/// Task 034: `engine`'s module memory maximum line: the bytes its run recorded
/// from the one memory check, or `none` when the module has no memory.
fn memory_maximum_line(engine: Engine, maximum: Option<u64>) -> String {
    match maximum {
        Some(bytes) => format!("{engine}_memory_maximum_bytes: {bytes}\n"),
        None => format!("{engine}_memory_maximum_bytes: none (the module has no memory)\n"),
    }
}

/// Write `run`'s receipt to `path` as a new file with the shared
/// [`write_new_file`]. Its refusal is returned unchanged.
pub fn write_receipt(run: &TwoEngineRun, path: &Path) -> Result<(), RunRefusal> {
    write_new_file(path, render(run).as_bytes())
}

/// Task 044: the stable reason id of `refusal`, and the engine its reason
/// names, if any. One exhaustive `match` per level, with no wildcard arm: a
/// new [`TwoEngineRefusal`] or [`Reason`] variant has no id until one is
/// written here, so it does not build. A version query's refusal, a memory
/// check's (task 033, [`TwoEngineRefusal::Memory`]) and a module run's carry
/// the same [`Reason`] type, so each [`Reason`] has one id.
pub fn refusal_reason(refusal: &TwoEngineRefusal) -> (&'static str, Option<Engine>) {
    let reason = match refusal {
        TwoEngineRefusal::Verify(_) => return ("verify_refused", None),
        TwoEngineRefusal::OutputsDiffer { .. } => return ("outputs_differ", None),
        TwoEngineRefusal::Version(refusal)
        | TwoEngineRefusal::Memory(refusal)
        | TwoEngineRefusal::Engine(refusal) => &refusal.reason,
    };
    match reason {
        Reason::EngineNotAbsolute => ("engine_not_absolute", None),
        Reason::WorkRootNotAbsolute => ("work_root_not_absolute", None),
        Reason::WorkRootUnresolved(_) => ("work_root_unresolved", None),
        Reason::WorkRootNotCanonical { .. } => ("work_root_not_canonical", None),
        Reason::WorkRootMetadataFailed(_) => ("work_root_metadata_failed", None),
        Reason::WorkRootNotAFolder => ("work_root_not_a_folder", None),
        Reason::RunDirExists => ("run_dir_exists", None),
        Reason::RunDirNotCreated(_) => ("run_dir_not_created", None),
        Reason::ModuleNotCreated(_) => ("module_not_created", None),
        Reason::ModuleNotWritten(_) => ("module_not_written", None),
        Reason::Writer(_) => ("writer_refused", None),
        Reason::EngineDidNotStart { engine, .. } => ("engine_did_not_start", Some(*engine)),
        Reason::EngineFailed { engine, .. } => ("engine_failed", Some(*engine)),
        Reason::VersionDidNotStart { engine, .. } => ("version_did_not_start", Some(*engine)),
        Reason::VersionFailed { engine, .. } => ("version_failed", Some(*engine)),
        Reason::VersionEmpty { engine } => ("version_empty", Some(*engine)),
        Reason::VersionNotPinned { engine, .. } => ("version_not_pinned", Some(*engine)),
        Reason::CapRejected { engine, .. } => ("cap_rejected", Some(*engine)),
        Reason::RunDirNotRemoved(_) => ("run_dir_not_removed", None),
        Reason::BudgetZero => ("budget_zero", None),
        Reason::BudgetExceeded { engine, .. } => ("budget_exceeded", Some(*engine)),
        Reason::EngineNotStopped { engine, .. } => ("engine_not_stopped", Some(*engine)),
        Reason::EngineNotWaited { engine, .. } => ("engine_not_waited", Some(*engine)),
        Reason::OutputNotRead { engine, .. } => ("output_not_read", Some(*engine)),
        Reason::MemoryNotRead(_) => ("memory_not_read", None),
        Reason::MemoryCountAboveOne { .. } => ("memory_count_above_one", None),
        Reason::MemoryMaximumMissing { .. } => ("memory_maximum_missing", None),
        Reason::MemoryMaximumAboveDeclared { .. } => ("memory_maximum_above_declared", None),
        Reason::Cancelled { engine } => (CANCELLED, Some(*engine)),
    }
}

/// Task 045: the reason id of a cancelled run, and its `outcome` value.
const CANCELLED: &str = "cancelled";

/// Task 045: the `outcome` of a refusal with the id `reason`: `cancelled` for
/// the cancel id, else `refused`. It reads only the id [`refusal_reason`] gave,
/// so there is no second rule for which refusal is a cancel.
fn refusal_outcome(reason: &str) -> &'static str {
    if reason == CANCELLED {
        CANCELLED
    } else {
        "refused"
    }
}

/// Task 044: the receipt of a refused run, as text. The lines and their order
/// are in the module docs; every value comes from `refusal`.
pub fn render_refused(refusal: &TwoEngineRefusal) -> String {
    let (reason, engine) = refusal_reason(refusal);
    format!(
        "schema: {REFUSAL_SCHEMA}\noutcome: {}\nreason: {reason}\nengine: {}\ndetail: \"{}\"\n",
        refusal_outcome(reason),
        engine.map_or("none", Engine::name),
        refusal.to_string().as_bytes().escape_ascii()
    )
}

/// Task 044: write `refusal`'s receipt to `path` as a new file with the
/// shared [`write_new_file`]. Its refusal is returned unchanged.
pub fn write_refused_receipt(refusal: &TwoEngineRefusal, path: &Path) -> Result<(), RunRefusal> {
    write_new_file(path, render_refused(refusal).as_bytes())
}
