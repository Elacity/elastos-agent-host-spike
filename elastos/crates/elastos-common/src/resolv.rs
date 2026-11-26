use std::path::Path;
fn keep(_: &Path) {}
pub static TEST_AFTER_OPEN: std::sync::Mutex<fn(&Path)> = std::sync::Mutex::new(keep);
thread_local! { static OPENED: std::cell::Cell<Option<Option<(u64, u64)>>> = const { std::cell::Cell::new(None) }; }
pub fn note_opened_resolv(path: &Path, id: Option<(u64, u64)>) {
    (TEST_AFTER_OPEN.lock().unwrap_or_else(|err| err.into_inner()))(path);
    OPENED.with(|slot| slot.set(Some(id)));
}
pub fn take_opened_resolv() -> Option<Option<(u64, u64)>> { OPENED.with(|slot| slot.replace(None)) }
