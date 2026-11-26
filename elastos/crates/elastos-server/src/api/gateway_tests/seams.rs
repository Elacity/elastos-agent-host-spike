//! Injectors keyed by one Home's data folder. A fault armed for one folder
//! cannot be taken by a test of another folder in the same process.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

fn guard<T>(slot: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|err| err.into_inner())
}

static RECORD_AUDIT: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static GRANT_FAULTS: LazyLock<Mutex<HashSet<(PathBuf, bool)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static GRANT_KINDS: LazyLock<Mutex<HashMap<PathBuf, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PARK_MS: LazyLock<Mutex<HashMap<PathBuf, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn arm_record_audit(data_dir: &Path) {
    guard(&RECORD_AUDIT).insert(data_dir.to_path_buf());
}

pub(crate) fn take_record_audit(data_dir: &Path) -> bool {
    guard(&RECORD_AUDIT).remove(data_dir)
}

/// `crash` is the gap after the approval row and before the mint.
/// The other fault is a failed approval append.
pub(crate) fn arm_grant_fault(data_dir: &Path, crash: bool) {
    guard(&GRANT_FAULTS).insert((data_dir.to_path_buf(), crash));
}

pub(crate) fn take_grant_fault(data_dir: &Path, crash: bool) -> bool {
    guard(&GRANT_FAULTS).remove(&(data_dir.to_path_buf(), crash))
}

/// One named fault for this Home: `before-send`, `after-mint`, `minted-row`,
/// `timeout`, `sent`, or `started`.
pub(crate) fn arm_grant_kind(data_dir: &Path, kind: &str) {
    guard(&GRANT_KINDS).insert(data_dir.to_path_buf(), kind.to_string());
}

pub(crate) fn grant_kind_is(data_dir: &Path, kind: &str) -> bool {
    guard(&GRANT_KINDS)
        .get(data_dir)
        .is_some_and(|held| held == kind)
}

pub(crate) fn take_grant_kind(data_dir: &Path, kind: &str) -> bool {
    let mut kinds = guard(&GRANT_KINDS);
    if kinds.get(data_dir).is_some_and(|held| held == kind) {
        kinds.remove(data_dir);
        return true;
    }
    false
}

/// One test millisecond stands for one second of this Home's plan park.
pub(crate) fn set_plan_park_ms(data_dir: &Path, ms: u64) {
    let mut parks = guard(&PARK_MS);
    if ms == 0 {
        parks.remove(data_dir);
    } else {
        parks.insert(data_dir.to_path_buf(), ms);
    }
}

pub(crate) fn plan_park_ms(data_dir: &Path) -> Option<u64> {
    guard(&PARK_MS).get(data_dir).copied().filter(|ms| *ms > 0)
}
