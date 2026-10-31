//! P6: a badge node showing a count.
//!
//! A [`Badge`] carries a count of 0 to [`MAX_SHOWN`]. A count above the
//! maximum is kept as "above range" and shown as `99+`; at 0 it is hidden; a
//! negative count is refused with `bad_badge_count`.
//!
//! Badges on host chrome are owned by the host. A [`HostChrome`] is set only by
//! the host seat: a capsule-originated set is refused with `host_chrome_badge`.
//! A capsule asks for a badge only by a Runtime capability request, never by
//! writing the chrome itself.
//!
//! Preset chosen here (the task gives none): [`MAX_SHOWN`] is a small
//! conservative 99, so counts 0 to 99 show as the number and anything above 99
//! shows `99+`.
//!
//! Refusals use one error enum, [`BadgeError`], whose [`BadgeError::code`]
//! table returns a stable snake_case code. Display renders
//! `<code>: <explanation>` with no host paths.

use std::fmt;

/// Highest count shown as its own number; above it a badge shows `99+`.
pub const MAX_SHOWN: u32 = 99;

/// Who is asking to set a badge on host chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The host itself, rendering its own chrome.
    Host,
    /// A capsule, which may only ask the Runtime for a badge.
    Capsule,
}

/// A refusal from this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeError {
    /// A count below zero was offered.
    BadBadgeCount,
    /// A capsule tried to set a badge on host chrome.
    HostChromeBadge,
}

impl BadgeError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BadgeError::BadBadgeCount => "bad_badge_count",
            BadgeError::HostChromeBadge => "host_chrome_badge",
        }
    }
}

impl fmt::Display for BadgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            BadgeError::BadBadgeCount => "a badge count cannot be negative",
            BadgeError::HostChromeBadge => "a capsule cannot set a badge on host chrome",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for BadgeError {}

/// The stored count of a badge: a number, or a marker for "above range".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stored {
    /// A count from 0 to [`MAX_SHOWN`], shown as its own number.
    Exact(u32),
    /// Any count above [`MAX_SHOWN`], shown as `99+`.
    AboveRange,
}

/// A badge node: a count 0 to [`MAX_SHOWN`], shown `99+` above it, hidden at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Badge {
    stored: Stored,
}

impl Badge {
    /// Build a badge from a raw count. A negative count is refused with
    /// `bad_badge_count`. A count of 0 yields a hidden badge. A count above
    /// [`MAX_SHOWN`] is kept as "above range".
    pub fn new(count: i64) -> Result<Badge, BadgeError> {
        if count < 0 {
            return Err(BadgeError::BadBadgeCount);
        }
        let stored = if count > MAX_SHOWN as i64 {
            Stored::AboveRange
        } else {
            Stored::Exact(count as u32)
        };
        Ok(Badge { stored })
    }

    /// The count this badge carries, capped at [`MAX_SHOWN`].
    pub fn count(&self) -> u32 {
        match self.stored {
            Stored::Exact(count) => count,
            Stored::AboveRange => MAX_SHOWN,
        }
    }

    /// A badge is hidden exactly when its count is 0.
    pub fn is_hidden(&self) -> bool {
        self.stored == Stored::Exact(0)
    }

    /// The label to render: the count, or `99+` when above [`MAX_SHOWN`].
    pub fn label(&self) -> Option<String> {
        match self.stored {
            Stored::Exact(0) => None,
            Stored::Exact(count) => Some(count.to_string()),
            Stored::AboveRange => Some(format!("{}+", MAX_SHOWN)),
        }
    }
}

/// A count that was set on host chrome: the badge and the surface that set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostChrome {
    badge: Badge,
}

impl HostChrome {
    /// A host chrome with no badge shown.
    pub fn new() -> HostChrome {
        HostChrome {
            badge: Badge {
                stored: Stored::Exact(0),
            },
        }
    }

    /// Set the badge for the given surface. Only [`Surface::Host`] may set a
    /// badge here; a capsule is refused with `host_chrome_badge`.
    pub fn set(&mut self, surface: Surface, count: i64) -> Result<(), BadgeError> {
        if surface == Surface::Capsule {
            return Err(BadgeError::HostChromeBadge);
        }
        self.badge = Badge::new(count)?;
        Ok(())
    }

    /// The badge currently on the host chrome.
    pub fn badge(&self) -> Badge {
        self.badge
    }
}

impl Default for HostChrome {
    fn default() -> HostChrome {
        HostChrome::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: a badge shows its own count from 0 to 99.
    #[test]
    fn shows_own_count_within_range() {
        assert_eq!(Badge::new(1).unwrap().label().as_deref(), Some("1"));
        assert_eq!(Badge::new(42).unwrap().label().as_deref(), Some("42"));
        assert_eq!(Badge::new(98).unwrap().label().as_deref(), Some("98"));
        assert_eq!(
            Badge::new(MAX_SHOWN as i64).unwrap().label().as_deref(),
            Some("99")
        );
    }

    // P6: a count above 99 shows 99+.
    #[test]
    fn shows_99_plus_above_range() {
        assert_eq!(Badge::new(100).unwrap().label().as_deref(), Some("99+"));
        assert_eq!(
            Badge::new(i64::MAX).unwrap().label().as_deref(),
            Some("99+")
        );
    }

    // P6: a badge is hidden at 0.
    #[test]
    fn hidden_at_zero() {
        let badge = Badge::new(0).unwrap();
        assert!(badge.is_hidden());
        assert_eq!(badge.label(), None);
    }

    // P6: negative counts are refused with bad_badge_count.
    #[test]
    fn negative_count_refused() {
        assert_eq!(Badge::new(-1).unwrap_err().code(), "bad_badge_count");
        assert_eq!(Badge::new(-99).unwrap_err().code(), "bad_badge_count");
    }

    // P6: host chrome badges are set by the host only.
    #[test]
    fn host_sets_host_chrome_badge() {
        let mut chrome = HostChrome::new();
        assert!(chrome.badge().is_hidden());
        chrome.set(Surface::Host, 7).unwrap();
        assert_eq!(chrome.badge().label().as_deref(), Some("7"));
    }

    // P6: a capsule cannot set a badge on host chrome.
    #[test]
    fn capsule_cannot_set_host_chrome_badge() {
        let mut chrome = HostChrome::new();
        assert_eq!(
            chrome.set(Surface::Capsule, 3).unwrap_err().code(),
            "host_chrome_badge"
        );
        assert!(chrome.badge().is_hidden());
    }

    // P6: codes are stable and distinct, and Display prefixes the code.
    #[test]
    fn codes_are_stable() {
        assert_eq!(BadgeError::BadBadgeCount.code(), "bad_badge_count");
        assert_eq!(BadgeError::HostChromeBadge.code(), "host_chrome_badge");
        assert!(BadgeError::BadBadgeCount
            .to_string()
            .starts_with(BadgeError::BadBadgeCount.code()));
        assert!(BadgeError::HostChromeBadge
            .to_string()
            .starts_with(BadgeError::HostChromeBadge.code()));
    }
}
