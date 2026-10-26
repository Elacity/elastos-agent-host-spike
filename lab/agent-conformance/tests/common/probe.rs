//! One component build path. Callers serialize builds: the script writes one entrypoint.

use agent_conformance::build::{lane, offline_build, repository};
use std::fs;

#[derive(Clone, Copy, Debug)]
pub enum Effect {
    Default,
    Read,
    HumanRead,
    MemoryWrite,
    Network,
    GrantedRead,
    SiblingRead,
    HostKeyRead,
    Task(u8),
    Runaway,
}

impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Read => "read",
            Self::HumanRead => "human-read",
            Self::MemoryWrite => "memory-write",
            Self::Network => "network",
            Self::GrantedRead => "granted-read",
            Self::SiblingRead => "sibling-read",
            Self::HostKeyRead => "host-key-read",
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
            Self::Read | Self::HumanRead => "-Dwarnings --cfg feature=\"read\"",
            Self::MemoryWrite => "-Dwarnings --cfg feature=\"memory-write\"",
            Self::Network => "-Dwarnings --cfg feature=\"network\"",
            Self::GrantedRead => "-Dwarnings --cfg feature=\"granted-read\"",
            Self::SiblingRead => "-Dwarnings --cfg feature=\"sibling-read\"",
            Self::HostKeyRead => "-Dwarnings --cfg feature=\"host-key-read\"",
            Self::Task(_) => "-Dwarnings --cfg feature=\"task\"",
            Self::Runaway => "-Dwarnings --cfg feature=\"runaway\"",
        }
    }
}

pub fn build_probe(effect: Effect, round: usize) -> Vec<u8> {
    let lane = lane();
    let root = repository();
    // Reuse dependencies and the componentizer for each selector. Remove only
    // the probe package before EVERY call, including both reproducibility rounds.
    let target = lane.join(format!("target/probe-build-{}", effect.name()));
    let cleaned = offline_build("cargo", &target)
        .unwrap_or_else(|error| skipped(&format!("prepare probe clean: {error}")))
        .args(["clean", "--manifest-path"])
        .arg(lane.join("probe/Cargo.toml"))
        .args([
            "--locked",
            "--offline",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "agent-conformance-probe",
        ])
        .output()
        .unwrap_or_else(|error| skipped(&format!("start probe clean: {error}")));
    if !cleaned.status.success() {
        skipped(&format!(
            "probe clean failed before launch: {}",
            cleaned.status
        ));
    }
    let output = offline_build("bash", &target)
        .unwrap_or_else(|error| skipped(&format!("prepare probe build: {error}")))
        .arg(root.join("scripts/build-component-capsule.sh"))
        .arg(lane.join("probe"))
        .env("RUSTFLAGS", effect.rustflags())
        .env(
            "AC_PROBE_READ_RESOURCE",
            match effect {
                Effect::HumanRead => include_str!("../../fixtures/human-read.txt"),
                _ => include_str!("../../fixtures/ungranted-read.txt"),
            }
            .trim(),
        )
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
        .unwrap_or_else(|error| skipped(&format!("start probe build: {error}")));
    if !output.status.success() {
        skipped(&format!(
            "probe build failed before launch: {}",
            output.status
        ));
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Compiling agent-conformance-probe v"),
        "probe round {round} must compile the package independently"
    );
    let artifact = fs::read(lane.join("probe/agent-conformance-probe.component.wasm"))
        .expect("the build script must produce the component");
    fs::remove_file(lane.join("probe/agent-conformance-probe.component.wasm")).unwrap();
    artifact
}

/// Only pre-probe setup calls this. Runtime refusals and assertions stay FAIL.
pub fn skipped(reason: &str) -> ! {
    let thread = std::thread::current();
    let name = thread.name().expect("libtest names each test thread");
    println!("SKIPPED {name}: {reason}");
    panic!("probe could not run");
}
