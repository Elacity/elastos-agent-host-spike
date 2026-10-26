//! One component build path. Callers serialize builds: the script writes one entrypoint.

use agent_conformance::build::{lane, offline_build, repository};
use std::fs;

#[derive(Clone, Copy, Debug)]
pub enum Effect {
    Default,
    Read,
    Network,
    Task(u8),
    Runaway,
}

impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Read => "read",
            Self::Network => "network",
            Self::Task(0) => "task-a",
            Self::Task(1) => "task-b",
            Self::Task(2) => "task-c",
            Self::Task(3) => "task-d",
            Self::Task(_) => panic!("only four task fixtures exist"),
            Self::Runaway => "runaway",
        }
    }

    fn rustflags(self) -> &'static str {
        // The repository script accepts RUSTFLAGS but has no --features input.
        // These cfg values select the declared Cargo features on the same source.
        match self {
            Self::Default => "-Dwarnings",
            Self::Read => "-Dwarnings --cfg feature=\"read\"",
            Self::Network => "-Dwarnings --cfg feature=\"network\"",
            Self::Task(_) => "-Dwarnings --cfg feature=\"task\"",
            Self::Runaway => "-Dwarnings --cfg feature=\"runaway\"",
        }
    }
}

pub fn build_probe(effect: Effect, round: usize) -> Vec<u8> {
    let lane = lane();
    let root = repository();
    let target = lane.join(format!("target/probe-build-{}-{round}", effect.name()));
    // Each round starts from an empty build directory: two cached reads are
    // insufficient evidence of reproducibility. All generated files are local.
    if target.exists() {
        fs::remove_dir_all(&target).unwrap();
    }
    let output = offline_build("bash", &target)
        .expect("prepare the probe build")
        .arg(root.join("scripts/build-component-capsule.sh"))
        .arg(lane.join("probe"))
        .env("RUSTFLAGS", effect.rustflags())
        .env(
            "AC_PROBE_TASK_INDEX",
            match effect {
                Effect::Task(index) => index,
                _ => 0,
            }
            .to_string(),
        )
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .expect("start the existing component build script");
    assert!(
        output.status.success(),
        "component build {round} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let artifact = fs::read(lane.join("probe/agent-conformance-probe.component.wasm"))
        .expect("the build script must produce the component");
    fs::remove_file(lane.join("probe/agent-conformance-probe.component.wasm")).unwrap();
    fs::remove_dir_all(target).unwrap();
    artifact
}
