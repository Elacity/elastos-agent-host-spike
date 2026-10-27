//! wc-005c: the receipt of a two-engine run, as lab text.
//!
//! [`render`] turns a [`TwoEngineRun`], which only [`crate::run::run`] makes,
//! into `key: value` lines in the shape of wc-001's build receipt
//! (`tools/build`), under its own schema line:
//!
//! ```text
//! schema: wc-005.run-receipt/v2
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
//! outcome: refused
//! reason: <the refusal's id, from refusal_reason>
//! engine: <wasmtime|wasmer|none>
//! detail: "<the refusal's Display>"
//! ```
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
pub const RECEIPT_SCHEMA: &str = "wc-005.run-receipt/v2";

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

/// Write `run`'s receipt to `path` as a new file with the shared
/// [`write_new_file`]. Its refusal is returned unchanged.
pub fn write_receipt(run: &TwoEngineRun, path: &Path) -> Result<(), RunRefusal> {
    write_new_file(path, render(run).as_bytes())
}

/// Task 044: the stable reason id of `refusal`, and the engine its reason
/// names, if any. One exhaustive `match` per level, with no wildcard arm: a
/// new [`TwoEngineRefusal`] or [`Reason`] variant has no id until one is
/// written here, so it does not build. A version query's refusal and a module
/// run's carry the same [`Reason`] type, so each [`Reason`] has one id.
pub fn refusal_reason(refusal: &TwoEngineRefusal) -> (&'static str, Option<Engine>) {
    let reason = match refusal {
        TwoEngineRefusal::Verify(_) => return ("verify_refused", None),
        TwoEngineRefusal::OutputsDiffer { .. } => return ("outputs_differ", None),
        TwoEngineRefusal::Version(refusal) | TwoEngineRefusal::Engine(refusal) => &refusal.reason,
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
    }
}

/// Task 044: the receipt of a refused run, as text. The lines and their order
/// are in the module docs; every value comes from `refusal`.
pub fn render_refused(refusal: &TwoEngineRefusal) -> String {
    let (reason, engine) = refusal_reason(refusal);
    format!(
        "schema: {REFUSAL_SCHEMA}\noutcome: refused\nreason: {reason}\nengine: {}\ndetail: \"{}\"\n",
        engine.map_or("none", Engine::name),
        refusal.to_string().as_bytes().escape_ascii()
    )
}

/// Task 044: write `refusal`'s receipt to `path` as a new file with the
/// shared [`write_new_file`]. Its refusal is returned unchanged.
pub fn write_refused_receipt(refusal: &TwoEngineRefusal, path: &Path) -> Result<(), RunRefusal> {
    write_new_file(path, render_refused(refusal).as_bytes())
}
