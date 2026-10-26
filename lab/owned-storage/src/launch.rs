//! Lab launcher for two agent instances.
//!
//! The real component launcher is `run_component_via_operator_runtime` in
//! `elastos/crates/elastos-server/src/run_cmd.rs`. It calls
//! `create_runtime("/tmp/elastos/storage")`. That function is `pub(crate)`,
//! and `elastos run` has no storage argument. This module prepares two
//! per-instance roots and does not start that command.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Grant, Refuse, Store};

/// The call the component launcher makes today.
pub const SHARED_TEMP_CONSTRUCTOR: &str = "create_runtime(\"/tmp/elastos/storage\")";

/// What `capsule_cmd.rs` already passes, and what `run` still does not.
pub const HOME_STORAGE_CONSTRUCTOR: &str =
    "create_runtime(crate::default_data_dir().join(\"storage\"))";

/// One real-Runtime row. `Blocked` is the only honest state until `elastos run`
/// takes a per-instance root and a component read returns a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState {
    Blocked,
    /// Set only by the shared-root plant's sibling, `F-A9-fake-runtime`.
    /// A live read refusal is still required before this counts.
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeRow {
    pub id: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeJourney {
    pub state: RowState,
    pub rows: &'static [RuntimeRow],
    /// A refusal string captured from a real component run. Empty until one runs.
    pub read_refusal: Option<String>,
    pub executed: bool,
}

/// `Blocked` while `elastos run` still builds the shared temp directory.
fn real_runtime_row_state() -> RowState {
    RowState::Blocked
}

const ROWS: &[RuntimeRow] = &[
    RuntimeRow {
        id: "real_runtime_each_instance_has_its_own_storage_root",
        reason: "BLOCKED AC-006-STORAGE: elastos run calls create_runtime(\"/tmp/elastos/storage\") and takes no per-instance root",
    },
    RuntimeRow {
        id: "real_runtime_agent_a_read_of_b_is_refused",
        reason: "BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider, so no component run can show a refusal from a per-instance root",
    },
];

/// How many times `run_cmd.rs` builds the shared temp directory.
pub fn shared_temp_constructor_count(run_cmd: &str) -> usize {
    run_cmd.matches(SHARED_TEMP_CONSTRUCTOR).count()
}

/// The storage field is kept and not used for object reads.
pub fn storage_provider_is_unused_for_reads(runtime_rs: &str) -> bool {
    runtime_rs.contains("_storage: Arc<dyn StorageProvider>")
        && runtime_rs.contains("before direct storage API calls are exposed from this layer")
}

pub fn real_runtime_journey() -> RuntimeJourney {
    RuntimeJourney {
        state: real_runtime_row_state(),
        rows: ROWS,
        read_refusal: None,
        executed: false,
    }
}

/// Two instance roots, and no Runtime process.
///
/// Starting `elastos run` would create `/tmp/elastos/storage` for both.
/// `elastos serve --storage-path` accepts a directory, and `Runtime` stores it
/// on `_storage`, which object reads do not use. This function does not call
/// either command.
pub fn prepare_instances(parent: &Path) -> Result<Prepared, Refuse> {
    let mut store = Store::open(parent)?;
    let agent_a = store.bind("agent-a", "session-a")?;
    let agent_b = store.bind("agent-b", "session-b")?;
    Ok(Prepared {
        store,
        agent_a,
        agent_b,
        journey: real_runtime_journey(),
    })
}

#[derive(Debug)]
pub struct Prepared {
    pub store: Store,
    pub agent_a: Grant,
    pub agent_b: Grant,
    pub journey: RuntimeJourney,
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repo root: {error}"))
}

pub fn read_repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// `elastos` is not installed here. A missing binary is not a successful run.
pub fn installed_elastos_binary() -> Option<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v elastos"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(text.trim());
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_runtime_rows_match_the_launcher() {
        let run_cmd = read_repo_file("elastos/crates/elastos-server/src/run_cmd.rs");
        let runtime_rs = read_repo_file("elastos/crates/elastos-server/src/runtime.rs");
        let proposal = include_str!("../PROPOSED-LAUNCHER-CHANGE.md");
        let count = shared_temp_constructor_count(&run_cmd);
        let unused = storage_provider_is_unused_for_reads(&runtime_rs);
        let journey = real_runtime_journey();
        let shared_before = Path::new(crate::SHARED_TEMP).exists();

        let parent = std::env::temp_dir().join(format!(
            "owned-storage-launch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&parent).unwrap();
        let prepared = prepare_instances(&parent).unwrap();
        let a_root = prepared
            .store
            .host_root(&prepared.agent_a)
            .unwrap()
            .to_path_buf();
        let b_root = prepared
            .store
            .host_root(&prepared.agent_b)
            .unwrap()
            .to_path_buf();

        match journey.state {
            RowState::Blocked => {
                assert!(
                    count > 0,
                    "rows stay blocked after elastos run stopped using {SHARED_TEMP_CONSTRUCTOR}"
                );
                assert_eq!(count, 3, "run_cmd.rs constructor count changed");
                assert!(
                    run_cmd.contains("fn run_component_via_operator_runtime"),
                    "component launcher function missing"
                );
                assert!(
                    unused,
                    "Runtime storage field changed; the blocked read row needs a new reading"
                );
                assert!(!journey.executed);
                assert!(journey.read_refusal.is_none());
                assert_eq!(prepared.journey, journey);
                let _installed = installed_elastos_binary();
                assert_eq!(journey.rows.len(), 2);
                for row in journey.rows {
                    assert!(
                        row.reason.starts_with("BLOCKED AC-006-STORAGE:"),
                        "{}",
                        row.id
                    );
                }
                assert_ne!(a_root, b_root);
                assert!(!a_root.starts_with(crate::SHARED_TEMP));
                assert!(!b_root.starts_with(crate::SHARED_TEMP));
                assert_eq!(Path::new(crate::SHARED_TEMP).exists(), shared_before);
                assert!(proposal.contains(HOME_STORAGE_CONSTRUCTOR));
                assert!(proposal.contains("BLOCKED"));
                assert!(proposal.contains("run_component_via_operator_runtime"));
            }
            RowState::Ready => {
                assert!(
                    count == 0,
                    "ready while elastos run still calls {SHARED_TEMP_CONSTRUCTOR}"
                );
                let reason = journey
                    .read_refusal
                    .as_deref()
                    .expect("ready without a runtime refusal reason");
                assert!(journey.executed);
                assert!(!reason.is_empty());
            }
        }

        drop(prepared);
        let _ = fs::remove_dir_all(&parent);
    }
}
