//! Lab launcher for two agent instances.
//!
//! The real component launcher is `run_component_via_operator_runtime` in
//! `elastos/crates/elastos-server/src/run_cmd.rs`. It calls
//! `create_runtime("/tmp/elastos/storage")`. That function is `pub(crate)`,
//! and `elastos run` has no storage argument. This module prepares two
//! per-instance roots and does not start that command.
//!
//! Lab rows and Runtime rows have separate grades. A host walk of sibling
//! roots is `NeedsConfinement`: the Store does not close same-uid mode 0755
//! access. That needs C3/C9 per-instance roots or the Runtime.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Grant, Refuse, Store};

/// The call the component launcher makes today.
pub const SHARED_TEMP_CONSTRUCTOR: &str = "create_runtime(\"/tmp/elastos/storage\")";

/// What `capsule_cmd.rs` already passes, and what `run` still does not.
pub const HOME_STORAGE_CONSTRUCTOR: &str =
    "create_runtime(crate::default_data_dir().join(\"storage\"))";

/// Which lane a graded row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Lab,
    Runtime,
    Host,
}

/// Lab rows may be `Ready`. Runtime rows stay `Blocked` until a live
/// component refusal exists. Host same-uid access is `NeedsConfinement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState {
    Blocked,
    /// Set only by the shared-root plant's sibling, `F-A9-fake-runtime`.
    /// A live read refusal is still required before a Runtime row counts.
    Ready,
    /// B's process can read, write, list and rename A's files on the host.
    /// The Store does not fix this.
    NeedsConfinement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GradedRow {
    pub id: &'static str,
    pub lane: Lane,
    pub state: RowState,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabJourney {
    pub state: RowState,
    pub rows: Vec<GradedRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeJourney {
    pub rows: Vec<GradedRow>,
    /// A refusal string captured from a real component run. Empty until one runs.
    pub read_refusal: Option<String>,
    pub executed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostJourney {
    pub state: RowState,
    pub reason: &'static str,
}

fn lab_row_state() -> RowState {
    RowState::Ready
}

fn real_runtime_root_row_state() -> RowState {
    RowState::Blocked
}

fn real_runtime_read_row_state() -> RowState {
    RowState::Blocked
}

fn host_row_state() -> RowState {
    RowState::NeedsConfinement
}

/// How many times a file builds the shared temp directory.
pub fn shared_temp_constructor_count(source: &str) -> usize {
    source.matches(SHARED_TEMP_CONSTRUCTOR).count()
}

/// The storage field is kept and not used for object reads.
pub fn storage_provider_is_unused_for_reads(runtime_rs: &str) -> bool {
    runtime_rs.contains("_storage: Arc<dyn StorageProvider>")
        && runtime_rs.contains("before direct storage API calls are exposed from this layer")
}

pub fn lab_journey() -> LabJourney {
    LabJourney {
        state: lab_row_state(),
        rows: vec![
            GradedRow {
                id: "lab_agent_cannot_read_or_write_another_agents_files",
                lane: Lane::Lab,
                state: lab_row_state(),
                reason: "lab Store read/write refusals are proven by this crate's tests",
            },
            GradedRow {
                id: "lab_agent_cannot_list_or_rename_another_agents_files",
                lane: Lane::Lab,
                state: lab_row_state(),
                reason: "lab Store list/rename refusals are proven by this crate's tests",
            },
        ],
    }
}

pub fn real_runtime_journey() -> RuntimeJourney {
    RuntimeJourney {
        rows: vec![
            GradedRow {
                id: "real_runtime_each_instance_has_its_own_storage_root",
                lane: Lane::Runtime,
                state: real_runtime_root_row_state(),
                reason: "BLOCKED AC-006-STORAGE: elastos run calls create_runtime(\"/tmp/elastos/storage\") and takes no per-instance root",
            },
            GradedRow {
                id: "real_runtime_agent_a_read_of_b_is_refused",
                lane: Lane::Runtime,
                state: real_runtime_read_row_state(),
                reason: "BLOCKED AC-006-STORAGE: agent file reads do not use that storage provider, so no component run can show a refusal from a per-instance root",
            },
        ],
        read_refusal: None,
        executed: false,
    }
}

pub fn host_journey() -> HostJourney {
    HostJourney {
        state: host_row_state(),
        reason: "NEEDS CONFINEMENT/RUNTIME: both agents run as the same uid; sibling roots are mode 0755; B's process can read, write, list and rename A's files on the host. The Store does not close this. C3/C9 per-instance roots or the Runtime must confine the process.",
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
        lab: lab_journey(),
        journey: real_runtime_journey(),
        host: host_journey(),
    })
}

#[derive(Debug)]
pub struct Prepared {
    pub store: Store,
    pub agent_a: Grant,
    pub agent_b: Grant,
    pub lab: LabJourney,
    pub journey: RuntimeJourney,
    pub host: HostJourney,
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
        let share_cmd = read_repo_file("elastos/crates/elastos-server/src/share_cmd.rs");
        let runtime_rs = read_repo_file("elastos/crates/elastos-server/src/runtime.rs");
        let proposal = include_str!("../PROPOSED-LAUNCHER-CHANGE.md");
        let run_count = shared_temp_constructor_count(&run_cmd);
        let share_count = shared_temp_constructor_count(&share_cmd);
        let unused = storage_provider_is_unused_for_reads(&runtime_rs);
        let lab = lab_journey();
        let journey = real_runtime_journey();
        let host = host_journey();
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

        assert_eq!(lab.state, RowState::Ready);
        assert!(lab.rows.iter().all(|row| row.lane == Lane::Lab));
        assert!(lab.rows.iter().all(|row| row.state == RowState::Ready));
        assert_eq!(host.state, RowState::NeedsConfinement);
        assert!(host.reason.contains("NEEDS CONFINEMENT/RUNTIME"));
        assert_eq!(prepared.lab, lab);
        assert_eq!(prepared.host, host);
        assert_eq!(prepared.journey, journey);

        assert_eq!(run_count, 3, "run_cmd.rs constructor count changed");
        assert_eq!(
            share_count, 1,
            "share_cmd.rs:183 must stay a fourth shared-temp site"
        );
        assert_eq!(
            run_count + share_count,
            4,
            "Runtime notes count four /tmp/elastos/storage sites"
        );
        assert!(
            share_cmd.contains(SHARED_TEMP_CONSTRUCTOR),
            "share_cmd.rs lost create_runtime(\"/tmp/elastos/storage\")"
        );
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
        assert_eq!(journey.rows.len(), 2);
        let _installed = installed_elastos_binary();

        for row in &journey.rows {
            assert_eq!(row.lane, Lane::Runtime, "{}", row.id);
            match (row.id, row.state) {
                (_, RowState::Blocked) => {
                    assert!(
                        row.reason.starts_with("BLOCKED AC-006-STORAGE:"),
                        "{}",
                        row.id
                    );
                    assert!(
                        run_count > 0,
                        "rows stay blocked after elastos run stopped using {SHARED_TEMP_CONSTRUCTOR}"
                    );
                }
                ("real_runtime_each_instance_has_its_own_storage_root", RowState::Ready) => {
                    assert_eq!(
                        run_count, 0,
                        "ready while elastos run still calls {SHARED_TEMP_CONSTRUCTOR}"
                    );
                }
                ("real_runtime_agent_a_read_of_b_is_refused", RowState::Ready) => {
                    let reason = journey
                        .read_refusal
                        .as_deref()
                        .expect("ready without a runtime refusal reason");
                    assert!(journey.executed);
                    assert!(!reason.is_empty());
                }
                (id, RowState::Ready) => panic!("unknown runtime row marked ready: {id}"),
                (id, RowState::NeedsConfinement) => {
                    panic!("runtime row {id} must stay Blocked or Ready, not host confinement")
                }
            }
        }

        assert_ne!(a_root, b_root);
        assert!(!a_root.starts_with(crate::SHARED_TEMP));
        assert!(!b_root.starts_with(crate::SHARED_TEMP));
        assert_eq!(Path::new(crate::SHARED_TEMP).exists(), shared_before);
        assert!(proposal.contains(HOME_STORAGE_CONSTRUCTOR));
        assert!(proposal.contains("BLOCKED"));
        assert!(proposal.contains("run_component_via_operator_runtime"));
        assert!(proposal.contains("share_cmd.rs"));
        assert!(proposal.contains("NEEDS CONFINEMENT/RUNTIME"));
        assert!(proposal.contains("four"));

        drop(prepared);
        let _ = fs::remove_dir_all(&parent);
    }
}
