//! `ui_sparkline`: a sparkline chart node (P6).
//!
//! A sparkline turns a short series of integer samples into integer
//! coordinates inside a caller-chosen `width` by `height` box. It carries no
//! host path, no network and no capability of its own: the caller (a UI
//! action owner) is responsible for turning a rendered sparkline into a
//! Runtime capability request; this node only computes geometry.
//!
//! Presets chosen conservatively (the task named none):
//! * at least 2 points, fewer are refused `too_few_points`;
//! * at most 500 points, more are refused `too_many_points`;
//! * `width` and `height` must both be at least 1, else `zero_width` or
//!   `zero_height`.
//!
//! Mapping: `x` walks `0..=width - 1` across the series; `y` maps the
//! maximum sample to `0` (top) and the minimum sample to `height - 1`
//! (bottom). A flat series (every sample equal) draws a centred horizontal
//! line at `height / 2`, so a sparkline of equal samples still yields a
//! visible line. Coordinates are clamped into `[0, width - 1] x [0, height - 1]`.
//!
//! The one error enum has one arm per variant in [`SparklineError::code`];
//! `Display` renders `<code>: <explanation>` and never embeds a host path.

use std::fmt;

/// The smallest number of points a sparkline accepts.
pub const MIN_POINTS: usize = 2;

/// The largest number of points a sparkline accepts.
pub const MAX_POINTS: usize = 500;

/// A refusal from the sparkline node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparklineError {
    /// Fewer than [`MIN_POINTS`] points were supplied.
    TooFewPoints { given: usize },
    /// More than [`MAX_POINTS`] points were supplied.
    TooManyPoints { given: usize },
    /// The requested width is zero.
    ZeroWidth,
    /// The requested height is zero.
    ZeroHeight,
}

impl SparklineError {
    /// The stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            SparklineError::TooFewPoints { .. } => "too_few_points",
            SparklineError::TooManyPoints { .. } => "too_many_points",
            SparklineError::ZeroWidth => "zero_width",
            SparklineError::ZeroHeight => "zero_height",
        }
    }
}

impl fmt::Display for SparklineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            SparklineError::TooFewPoints { given } => format!(
                "a sparkline needs at least {} points, got {}",
                MIN_POINTS, given
            ),
            SparklineError::TooManyPoints { given } => format!(
                "a sparkline accepts at most {} points, got {}",
                MAX_POINTS, given
            ),
            SparklineError::ZeroWidth => "sparkline width must be at least 1".to_string(),
            SparklineError::ZeroHeight => "sparkline height must be at least 1".to_string(),
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for SparklineError {}

/// One integer coordinate inside the sparkline box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: i64,
    pub y: i64,
}

/// A validated series of integer samples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sparkline {
    points: Vec<i64>,
}

impl Sparkline {
    /// Builds a sparkline from integer samples.
    ///
    /// Refuses fewer than [`MIN_POINTS`] or more than [`MAX_POINTS`] points.
    pub fn new(points: Vec<i64>) -> Result<Self, SparklineError> {
        if points.len() < MIN_POINTS {
            return Err(SparklineError::TooFewPoints {
                given: points.len(),
            });
        }
        if points.len() > MAX_POINTS {
            return Err(SparklineError::TooManyPoints {
                given: points.len(),
            });
        }
        Ok(Self { points })
    }

    /// The number of samples in this sparkline.
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// True when the sparkline carries no samples; a validated `Sparkline`
    /// never is empty, so this always returns false.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// The samples, in order.
    pub fn points(&self) -> &[i64] {
        &self.points
    }

    /// Renders the series into integer coordinates inside a `width` by
    /// `height` box.
    ///
    /// `x` walks `0..=width - 1`, `y` sits in `0..=height - 1`. The maximum
    /// sample maps to `y = 0` (top) and the minimum sample to
    /// `y = height - 1` (bottom). A flat series (every sample equal) draws a
    /// centred line at `height / 2`.
    pub fn render(&self, width: i64, height: i64) -> Result<Vec<Point>, SparklineError> {
        if width < 1 {
            return Err(SparklineError::ZeroWidth);
        }
        if height < 1 {
            return Err(SparklineError::ZeroHeight);
        }

        let n = self.points.len() as i64;
        let min = *self.points.iter().min().expect("non-empty");
        let max = *self.points.iter().max().expect("non-empty");
        let flat = min == max;
        let span = max.saturating_sub(min);

        let mut out = Vec::with_capacity(self.points.len());
        for (i, sample) in self.points.iter().enumerate() {
            // Spread samples across the full box width, 0..=width-1.
            let x = if n <= 1 {
                0
            } else {
                (i as i64) * (width - 1) / (n - 1)
            };
            let y = if flat || span == 0 {
                height / 2
            } else {
                // Highest sample sits at y = 0 (top), lowest at height - 1.
                let rel = sample - min;
                (height - 1) - rel * (height - 1) / span
            };
            out.push(Point {
                x: clamp(x, 0, width - 1),
                y: clamp(y, 0, height - 1),
            });
        }
        Ok(out)
    }
}

fn clamp(value: i64, lo: i64, hi: i64) -> i64 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: fewer than two points is refused with the stable code.
    #[test]
    fn one_point_is_refused_too_few_points() {
        let err = Sparkline::new(vec![7]).unwrap_err();
        assert_eq!(err.code(), "too_few_points");
    }

    // P6: zero samples is refused with the stable code.
    #[test]
    fn zero_points_is_refused_too_few_points() {
        let err = Sparkline::new(Vec::new()).unwrap_err();
        assert_eq!(err.code(), "too_few_points");
    }

    // P6: more than the documented cap is refused.
    #[test]
    fn too_many_points_is_refused() {
        let many: Vec<i64> = (0..(MAX_POINTS as i64 + 1)).collect();
        let err = Sparkline::new(many).unwrap_err();
        assert_eq!(err.code(), "too_many_points");
    }

    // P6: two points is the accepted lower bound.
    #[test]
    fn two_points_is_accepted() {
        let spark = Sparkline::new(vec![0, 10]).expect("two points are accepted");
        assert_eq!(spark.len(), 2);
        assert!(!spark.is_empty());
    }

    // P6: the documented upper bound is accepted, one past it is not.
    #[test]
    fn max_points_boundary_is_accepted() {
        let at_cap: Vec<i64> = (0..(MAX_POINTS as i64)).collect();
        assert!(Sparkline::new(at_cap).is_ok());
    }

    // P6 / zero-limit test: a zero width or height is refused with its code.
    #[test]
    fn zero_limits_are_refused() {
        let spark = Sparkline::new(vec![1, 2, 3]).expect("three points are accepted");
        assert_eq!(spark.render(0, 10).unwrap_err().code(), "zero_width");
        assert_eq!(spark.render(10, 0).unwrap_err().code(), "zero_height");
        assert_eq!(spark.render(0, 0).unwrap_err().code(), "zero_width");
    }

    // P6: a flat series draws a centred horizontal line.
    #[test]
    fn flat_series_draws_centred_line() {
        let spark = Sparkline::new(vec![5, 5, 5, 5]).expect("flat series is accepted");
        let coords = spark.render(9, 7).expect("non-zero size renders");
        assert_eq!(coords.len(), 4);
        for point in &coords {
            assert_eq!(point.y, 3, "flat series sits at height / 2");
        }
        assert_eq!(coords.first().unwrap().x, 0);
        assert_eq!(coords.last().unwrap().x, 8);
    }

    // P6: ascending series starts at bottom-left (lowest sample) and ends at
    // top-right (highest sample), since y = 0 is the top of the box.
    #[test]
    fn ascending_series_spans_corners() {
        let spark = Sparkline::new(vec![0, 5, 10]).expect("ascending series is accepted");
        let coords = spark.render(5, 5).expect("non-zero size renders");
        assert_eq!(coords.first().unwrap(), &Point { x: 0, y: 4 });
        assert_eq!(coords.last().unwrap(), &Point { x: 4, y: 0 });
        // Y never increases as samples increase: larger samples sit higher.
        for pair in coords.windows(2) {
            assert!(pair[0].y >= pair[1].y, "monotone ascent to the top");
        }
    }

    // P6: every coordinate lies inside the box for an arbitrary series.
    #[test]
    fn all_coordinates_stay_inside_box() {
        let spark = Sparkline::new(vec![-3, 100, 0, 42, -7, 8])
            .expect("mixed series is accepted");
        let (w, h) = (11, 4);
        let coords = spark.render(w, h).expect("non-zero size renders");
        assert_eq!(coords.len(), spark.len());
        for point in &coords {
            assert!((0..w).contains(&point.x), "x within width");
            assert!((0..h).contains(&point.y), "y within height");
        }
    }

    // P6: the width-one box collapses x to a single column, no panic.
    #[test]
    fn width_one_is_a_single_column() {
        let spark = Sparkline::new(vec![1, 9, 4]).expect("three points are accepted");
        let coords = spark.render(1, 6).expect("non-zero size renders");
        for point in &coords {
            assert_eq!(point.x, 0);
        }
    }

    // P6: refusal codes are exactly the task's snake_case names.
    #[test]
    fn refusal_codes_are_stable() {
        assert_eq!(
            SparklineError::TooFewPoints { given: 1 }.code(),
            "too_few_points"
        );
        assert_eq!(
            SparklineError::TooManyPoints { given: 501 }.code(),
            "too_many_points"
        );
        assert_eq!(SparklineError::ZeroWidth.code(), "zero_width");
        assert_eq!(SparklineError::ZeroHeight.code(), "zero_height");
    }
}
