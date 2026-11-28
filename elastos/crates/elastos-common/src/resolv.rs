thread_local! { static OPENED: std::cell::Cell<Option<Option<(u64, u64)>>> = const { std::cell::Cell::new(None) }; }
pub fn note_opened_resolv(id: Option<(u64, u64)>) {
    OPENED.with(|slot| slot.set(Some(id)));
}
pub fn take_opened_resolv() -> Option<Option<(u64, u64)>> { OPENED.with(|slot| slot.replace(None)) }
