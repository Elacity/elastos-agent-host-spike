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
