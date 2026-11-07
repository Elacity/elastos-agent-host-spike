//! Task 064: the Runtime's own componentize tool, `elastos/tools/componentize`,
//! run read-only, as `scripts/build-component-capsule.sh` runs it. Nothing of
//! the tool is copied, vendored or patched here, and the lab lockfile holds
//! none of its crates: this helper only runs it.

use super::build::{lane_dir, TempDir};
use std::fs;
use std::process::{Command, ExitStatus};
use std::sync::Mutex;

/// What one run of the Runtime's componentize tool gave: its exit status, its
/// stderr, and the component it wrote (`None` when it wrote none).
#[derive(Clone, Debug)]
pub struct Componentized {
    pub status: ExitStatus,
    pub stderr: String,
    pub component: Option<Vec<u8>>,
}

/// Wrap the core module `core` with the Runtime's componentize tool: `cargo
/// run --quiet --locked --offline --manifest-path
/// <repo>/elastos/tools/componentize/Cargo.toml -- <in> <out>`. The tool's
/// own `Cargo.lock` is used and never written (`--locked`), and nothing is
/// fetched (`--offline`). Its build goes into `target/componentize` under this
/// lane (git-ignored), never under `elastos/`, and the input and output files
/// are in a temp folder removed after the run.
///
/// Each distinct `core` is run at most once per test binary: the result is
/// kept and given again. The lock also keeps two runs from building at once.
pub fn componentize(core: &[u8]) -> Componentized {
    static RUNS: Mutex<Vec<(Vec<u8>, Componentized)>> = Mutex::new(Vec::new());
    let mut runs = RUNS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, done)) = runs.iter().find(|(input, _)| input == core) {
        return done.clone();
    }
    let done = run_componentize(core);
    runs.push((core.to_vec(), done.clone()));
    done
}

fn run_componentize(core: &[u8]) -> Componentized {
    let lane = lane_dir();
    let manifest = lane.join("../../elastos/tools/componentize/Cargo.toml");
    let tmp = TempDir::new("componentize");
    let input = tmp.path().join("core.wasm");
    let output = tmp.path().join("out.component.wasm");
    fs::write(&input, core).expect("write the core module for componentize");
    let ran = Command::new("cargo")
        .args(["run", "--quiet", "--locked", "--offline", "--manifest-path"])
        .arg(&manifest)
        .arg("--")
        .arg(&input)
        .arg(&output)
        .env("CARGO_TARGET_DIR", lane.join("target").join("componentize"))
        .output()
        .expect("spawn cargo run for the Runtime's componentize tool");
    Componentized {
        status: ran.status,
        stderr: String::from_utf8_lossy(&ran.stderr).into_owned(),
        component: fs::read(&output).ok(),
    }
}
