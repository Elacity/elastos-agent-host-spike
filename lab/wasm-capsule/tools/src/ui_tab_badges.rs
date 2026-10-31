//! Capsule-set count badges on the wasm-capsule lab's own tab strip.
//!
//! A capsule may ask a tab to show a count badge. The badge is a display
//! hint only: it carries no DDRM, licence or price meaning, and no Runtime
//! admission or launch path reads it. It maps to a UI action that resolves to
//! a Runtime capability request (P6): the capsule names a tab id, the host
//! decides what, if anything, the strip draws.
//!
//! Preset chosen here (the task does not give one), conservative: a count
//! badge is clipped to `MAX_SHOWN_COUNT` (99) and rendered as `99+` above
//! that; a badge on the currently active tab is hidden; a tab id not on the
//! strip is refused with `unknown_tab`.
//!
//! A strip starts with no active tab, so every badge set is shown until
//! `set_active` names the tab that is active. Tab ids must be unique, so the
//! hidden rule has exactly one tab to apply to.
//!
//! [`TabBadges`] holds the strip's tab ids and badges. Every refusal goes
//! through [`BadgeError`], whose [`BadgeError::code`] table is the only
//! stable name for a refusal; `Display` renders `<code>: <explanation>`.

use std::fmt;

/// Counts above this are clipped and shown as `99+`.
pub const MAX_SHOWN_COUNT: u32 = 99;

/// The clipped text for any shown count.
pub fn badge_label(count: u32) -> String {
    if count > MAX_SHOWN_COUNT {
        format!("{}+", MAX_SHOWN_COUNT)
    } else {
        count.to_string()
    }
}

/// One refusal raised by [`TabBadges`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadgeError {
    /// The capsule named a tab id that is not on the strip.
    UnknownTab,
    /// The strip was built with the same tab id twice.
    DuplicateTab,
}

impl BadgeError {
    /// The stable snake_case name of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BadgeError::UnknownTab => "unknown_tab",
            BadgeError::DuplicateTab => "duplicate_tab",
        }
    }
}

impl fmt::Display for BadgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            BadgeError::UnknownTab => "no tab with that id is on the strip",
            BadgeError::DuplicateTab => "the strip was given the same tab id twice",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for BadgeError {}

/// The tab strip's ids and the count each tab's badge carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabBadges {
    tabs: Vec<String>,
    counts: Vec<Option<u32>>,
    active: Option<usize>,
}

impl TabBadges {
    /// A strip with these tab ids, no tab active, no badges set.
    ///
    /// Refuses `duplicate_tab` when a tab id appears twice.
    pub fn new<I, S>(tabs: I) -> Result<Self, BadgeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let tabs: Vec<String> = tabs.into_iter().map(Into::into).collect();
        for (i, tab) in tabs.iter().enumerate() {
            if tabs[..i].iter().any(|t| t == tab) {
                return Err(BadgeError::DuplicateTab);
            }
        }
        let counts = vec![None; tabs.len()];
        Ok(TabBadges {
            tabs,
            counts,
            active: None,
        })
    }

    /// The strip's tab ids, in order.
    pub fn tab_ids(&self) -> Vec<String> {
        self.tabs.clone()
    }

    /// The active tab's id, if any.
    pub fn active_tab(&self) -> Option<&str> {
        self.active.map(|i| self.tabs[i].as_str())
    }

    /// Set the count badge of `tab_id`; `None` clears it.
    pub fn set_count(&mut self, tab_id: &str, count: Option<u32>) -> Result<(), BadgeError> {
        let index = self.index_of(tab_id)?;
        self.counts[index] = count;
        Ok(())
    }

    /// Record which tab is active; its badge is hidden while it is active.
    pub fn set_active(&mut self, tab_id: &str) -> Result<(), BadgeError> {
        let index = self.index_of(tab_id)?;
        self.active = Some(index);
        Ok(())
    }

    /// Clear the active tab; thereafter every badge is shown.
    pub fn clear_active(&mut self) {
        self.active = None;
    }

    /// The text the strip draws for `tab_id`, or `None` when it draws none:
    /// no badge set, or the tab is active (its badge is hidden).
    pub fn badge_text(&self, tab_id: &str) -> Result<Option<String>, BadgeError> {
        let index = self.index_of(tab_id)?;
        if self.active == Some(index) {
            return Ok(None);
        }
        Ok(self.counts[index].map(badge_label))
    }

    fn index_of(&self, tab_id: &str) -> Result<usize, BadgeError> {
        self.tabs
            .iter()
            .position(|t| t == tab_id)
            .ok_or(BadgeError::UnknownTab)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: a capsule-set count is drawn on its tab's badge, and only there.
    #[test]
    fn capsule_count_is_shown_on_its_tab() {
        let mut badges = TabBadges::new(["home", "files"]).unwrap();
        assert_eq!(badges.badge_text("home").unwrap(), None);
        badges.set_count("files", Some(7)).unwrap();
        assert_eq!(badges.badge_text("files").unwrap(), Some("7".to_string()));
        assert_eq!(badges.badge_text("home").unwrap(), None);
    }

    // P6: counts above 99 are shown clipped as 99+.
    #[test]
    fn counts_above_99_are_shown_as_99_plus() {
        let mut badges = TabBadges::new(["home", "files"]).unwrap();
        badges.set_count("files", Some(100)).unwrap();
        assert_eq!(badges.badge_text("files").unwrap(), Some("99+".to_string()));
        badges.set_count("files", Some(99)).unwrap();
        assert_eq!(badges.badge_text("files").unwrap(), Some("99".to_string()));
        badges.set_count("files", Some(1_000_000)).unwrap();
        assert_eq!(badges.badge_text("files").unwrap(), Some("99+".to_string()));
    }

    // P6: a badge on the active tab is hidden, and shown again when that tab
    // is no longer active. The badge is drawn before the tab is active,
    // hidden while it is active, and drawn again afterwards.
    #[test]
    fn active_tab_badge_is_hidden() {
        let mut badges = TabBadges::new(["home", "files"]).unwrap();
        badges.set_count("home", Some(3)).unwrap();
        assert_eq!(badges.badge_text("home").unwrap(), Some("3".to_string()));
        badges.set_active("home").unwrap();
        assert_eq!(badges.active_tab(), Some("home"));
        assert_eq!(badges.badge_text("home").unwrap(), None);
        badges.set_active("files").unwrap();
        assert_eq!(badges.active_tab(), Some("files"));
        assert_eq!(badges.badge_text("home").unwrap(), Some("3".to_string()));
        badges.clear_active();
        assert_eq!(badges.active_tab(), None);
        assert_eq!(badges.badge_text("home").unwrap(), Some("3".to_string()));
    }

    // P6: an unknown tab id is refused with the unknown_tab code, never a
    // Display string or host path.
    #[test]
    fn unknown_tab_is_refused() {
        let mut badges = TabBadges::new(["home", "files"]).unwrap();
        let err = badges.set_count("ghost", Some(1)).unwrap_err();
        assert_eq!(err.code(), "unknown_tab");
        let err = badges.set_active("ghost").unwrap_err();
        assert_eq!(err.code(), "unknown_tab");
        let err = badges.badge_text("ghost").unwrap_err();
        assert_eq!(err.code(), "unknown_tab");
    }

    // P6: a duplicate tab id is refused, so the active tab is unambiguous.
    #[test]
    fn duplicate_tab_is_refused() {
        let err = TabBadges::new(["home", "files", "home"]).unwrap_err();
        assert_eq!(err.code(), "duplicate_tab");
    }

    // P6: clearing a badge removes it from the strip.
    #[test]
    fn clearing_a_badge_hides_it() {
        let mut badges = TabBadges::new(["home", "files"]).unwrap();
        badges.set_count("files", Some(5)).unwrap();
        badges.set_count("files", None).unwrap();
        assert_eq!(badges.badge_text("files").unwrap(), None);
    }
}
