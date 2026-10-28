//! A star rating input node (P6 UI action). Self-contained types: it holds
//! its own configuration and value, and emits events that carry the value
//! only. It never talks to Runtime, network or host, and never holds a host
//! path. A UI action here resolves to a Runtime capability request made by
//! the caller; this node only names the value the caller asks for.
//!
//! Defaults chosen here (the task gives none):
//! - `max_stars` = 5, the most common star rating length.
//! - half steps are disabled by default so value is a whole star count.

use std::fmt;

/// Why a star rating node refused a configuration or value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StarRatingError {
    /// `max_stars` was outside the 3 to 10 range.
    BadStarCount { max_stars: u8 },
    /// A value was outside 0..=max, off a half step, or not finite.
    BadRatingValue { value: f32, max_stars: u8, half_steps: bool },
}

impl StarRatingError {
    /// Stable snake_case refusal code. Tests assert this, never Display.
    pub fn code(&self) -> &'static str {
        match self {
            StarRatingError::BadStarCount { .. } => "bad_star_count",
            StarRatingError::BadRatingValue { .. } => "bad_rating_value",
        }
    }
}

impl fmt::Display for StarRatingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: String = match self {
            StarRatingError::BadStarCount { max_stars } => format!(
                "star count {} is outside the allowed 3 to 10 stars",
                max_stars
            ),
            StarRatingError::BadRatingValue {
                value,
                max_stars,
                half_steps,
            } => {
                let step = if *half_steps { "half" } else { "whole" };
                format!(
                    "rating value {} is outside 0 to {} or not on a {} step",
                    value, max_stars, step
                )
            }
        };
        write!(f, "{}: {}", self.code(), text)
    }
}

/// The event a star rating node emits. It carries the value only.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StarRatingEvent {
    /// The value changed to this value, in stars.
    Changed { value: f32 },
}

/// Immutable configuration of a star rating node.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StarRatingConfig {
    max_stars: u8,
    half_steps: bool,
}

impl StarRatingConfig {
    /// Minimum number of stars a rating node may show.
    pub const MIN_STARS: u8 = 3;
    /// Maximum number of stars a rating node may show.
    pub const MAX_STARS: u8 = 10;

    /// Build a configuration. `max_stars` must be 3 to 10 inclusive.
    pub fn new(max_stars: u8, half_steps: bool) -> Result<Self, StarRatingError> {
        if !(Self::MIN_STARS..=Self::MAX_STARS).contains(&max_stars) {
            return Err(StarRatingError::BadStarCount { max_stars });
        }
        Ok(StarRatingConfig {
            max_stars,
            half_steps,
        })
    }

    /// Number of stars this node shows.
    pub fn max_stars(&self) -> u8 {
        self.max_stars
    }

    /// Whether half steps are allowed.
    pub fn half_steps(&self) -> bool {
        self.half_steps
    }
}

/// A star rating input node holding a value in stars.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StarRatingNode {
    config: StarRatingConfig,
    value: f32,
}

impl StarRatingNode {
    /// A node starting at zero for the given configuration.
    pub fn new(config: StarRatingConfig) -> Self {
        StarRatingNode { config, value: 0.0 }
    }

    /// The configuration this node uses.
    pub fn config(&self) -> StarRatingConfig {
        self.config
    }

    /// The current value in stars.
    pub fn value(&self) -> f32 {
        self.value
    }

    /// Set the value. Refuses a value outside 0..=max, off a half step when
    /// half steps are disabled, or not finite. On success returns the event
    /// carrying the value only.
    pub fn set_value(&mut self, value: f32) -> Result<StarRatingEvent, StarRatingError> {
        if !value.is_finite()
            || value < 0.0
            || value > f32::from(self.config.max_stars)
            || (!self.config.half_steps && (value * 2.0) % 2.0 != 0.0)
        {
            return Err(StarRatingError::BadRatingValue {
                value,
                max_stars: self.config.max_stars,
                half_steps: self.config.half_steps,
            });
        }
        self.value = value;
        Ok(StarRatingEvent::Changed { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: a star count below the 3 to 10 window is refused with bad_star_count.
    #[test]
    fn star_count_below_three_is_refused() {
        let err = StarRatingConfig::new(2, false).unwrap_err();
        assert_eq!(err.code(), "bad_star_count");
    }

    // P6: a star count above 10 is refused with bad_star_count.
    #[test]
    fn star_count_above_ten_is_refused() {
        let err = StarRatingConfig::new(11, false).unwrap_err();
        assert_eq!(err.code(), "bad_star_count");
    }

    // P6: every count in the 3 to 10 window is accepted.
    #[test]
    fn star_count_in_window_is_accepted() {
        for n in StarRatingConfig::MIN_STARS..=StarRatingConfig::MAX_STARS {
            let cfg = StarRatingConfig::new(n, true).unwrap();
            assert_eq!(cfg.max_stars(), n);
        }
    }

    // P6: a value above max is refused with bad_rating_value.
    #[test]
    fn value_above_max_is_refused() {
        let cfg = StarRatingConfig::new(5, false).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let err = node.set_value(6.0).unwrap_err();
        assert_eq!(err.code(), "bad_rating_value");
    }

    // P6: a negative value is refused with bad_rating_value.
    #[test]
    fn negative_value_is_refused() {
        let cfg = StarRatingConfig::new(5, false).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let err = node.set_value(-1.0).unwrap_err();
        assert_eq!(err.code(), "bad_rating_value");
    }

    // P6: a non finite value is refused with bad_rating_value.
    #[test]
    fn non_finite_value_is_refused() {
        let cfg = StarRatingConfig::new(5, true).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let err = node.set_value(f32::NAN).unwrap_err();
        assert_eq!(err.code(), "bad_rating_value");
    }

    // P6: whole star values in range are accepted and echoed in the event.
    #[test]
    fn whole_value_in_range_is_accepted() {
        let cfg = StarRatingConfig::new(5, false).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let ev = node.set_value(3.0).unwrap();
        assert_eq!(ev, StarRatingEvent::Changed { value: 3.0 });
        assert_eq!(node.value(), 3.0);
    }

    // P6: with half steps off, a half value is refused.
    #[test]
    fn half_value_refused_without_half_steps() {
        let cfg = StarRatingConfig::new(5, false).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let err = node.set_value(2.5).unwrap_err();
        assert_eq!(err.code(), "bad_rating_value");
    }

    // P6: with half steps on, a half value is accepted and echoed.
    #[test]
    fn half_value_accepted_with_half_steps() {
        let cfg = StarRatingConfig::new(5, true).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let ev = node.set_value(2.5).unwrap();
        assert_eq!(ev, StarRatingEvent::Changed { value: 2.5 });
        assert_eq!(node.value(), 2.5);
    }

    // P6: zero is a valid value (no stars chosen) and travels in the event.
    #[test]
    fn zero_value_is_accepted() {
        let cfg = StarRatingConfig::new(7, true).unwrap();
        let mut node = StarRatingNode::new(cfg);
        let ev = node.set_value(0.0).unwrap();
        assert_eq!(ev, StarRatingEvent::Changed { value: 0.0 });
    }

    // P6: a refused set does not change the stored value.
    #[test]
    fn refused_set_keeps_previous_value() {
        let cfg = StarRatingConfig::new(4, false).unwrap();
        let mut node = StarRatingNode::new(cfg);
        node.set_value(2.0).unwrap();
        let _ = node.set_value(9.0).unwrap_err();
        assert_eq!(node.value(), 2.0);
    }

    // P6: Display of a refusal starts with its stable code.
    #[test]
    fn display_starts_with_code() {
        let err = StarRatingError::BadStarCount { max_stars: 12 };
        assert!(err.to_string().starts_with("bad_star_count: "));
    }
}
