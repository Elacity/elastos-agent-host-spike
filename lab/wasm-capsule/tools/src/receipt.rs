//! wc-005c: the receipt of a two-engine run, as lab text.
//!
//! [`render`] turns a [`TwoEngineRun`], which only [`crate::run::run`] makes,
//! into `key: value` lines in the shape of wc-001's build receipt
//! (`tools/build`), under its own schema line:
//!
//! ```text
//! schema: wc-005.run-receipt/v1
//! bundle: <the verified lab CID, as its Display form>
//! function: digest
//! argument: 1592590337
//! wasmtime_version: "<the first line wasmtime --version printed>"
//! wasmtime_status: <the module run's exit status>
//! wasmtime_stdout: "<what the module run printed>"
//! wasmer_version: "..."
//! wasmer_status: ...
//! wasmer_stdout: "..."
//! ```
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

use crate::bundle::{write_new_file, RunRefusal};
use crate::run::{Engine, TwoEngineRun, DIGEST_ARGUMENT, DIGEST_EXPORT};
use std::path::Path;

/// The receipt's schema line value.
pub const RECEIPT_SCHEMA: &str = "wc-005.run-receipt/v1";

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
    receipt
}

/// Write `run`'s receipt to `path` as a new file with the shared
/// [`write_new_file`]. Its refusal is returned unchanged.
pub fn write_receipt(run: &TwoEngineRun, path: &Path) -> Result<(), RunRefusal> {
    write_new_file(path, render(run).as_bytes())
}
