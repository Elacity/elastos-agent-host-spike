//! `version_monotonic`: P15's install-time version gate for a capsule manifest.
//!
//! Installing a manifest whose version is lower than or equal to the
//! installed one is refused with `version_not_newer` unless the owner chose a
//! downgrade. The choice is a typed [`DowngradeChoice`], never a bare bool, so
//! a caller cannot pass a stray `true` by accident.
//!
//! Versions are compared numerically per dot-separated segment, not as
//! strings: `1.10.0` is newer than `1.9.0`, and `01` equals `1`. Segments are
//! ASCII digits only; an empty string, an empty segment, a non-digit character
//! or a numeric overflow is refused with `malformed_version` rather than
//! guessed at.
//!
//! This is a lab check only. No Runtime admission or launch path calls it.

use std::cmp::Ordering;
use std::fmt;

/// The most segments a version may carry. A version with more segments than
/// this is refused as `malformed_version` instead of being compared on a
/// prefix. Chosen small and conservative: eight segments covers the common
/// `major.minor.patch.build` shape with headroom.
const MAX_SEGMENTS: usize = 8;

/// Any refusal of the install-time version gate. One variant per stable
/// snake_case code; see [`VersionError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    /// The incoming version is not numerically greater than the installed
    /// one, and the owner did not choose a downgrade.
    VersionNotNewer,
    /// A version string is not dot-separated ASCII digit segments within
    /// [`MAX_SEGMENTS`], or a segment overflows `u64`.
    MalformedVersion,
}

impl VersionError {
    /// The stable refusal code. Tests assert this, never the Display text.
    pub fn code(&self) -> &'static str {
        match self {
            VersionError::VersionNotNewer => "version_not_newer",
            VersionError::MalformedVersion => "malformed_version",
        }
    }
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            VersionError::VersionNotNewer => {
                "the incoming manifest version is not newer than the installed one"
            }
            VersionError::MalformedVersion => {
                "a manifest version is not dot-separated digits within the segment limit"
            }
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for VersionError {}

/// The owner's typed answer to "is a downgrade allowed here?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeChoice {
    /// Only a strictly newer version may be installed.
    Refuse,
    /// The owner chose a downgrade; an equal or lower version is accepted.
    Allow,
}

/// Compare two version strings numerically per segment.
///
/// Returns the ordering of `installed` against `incoming`, so a strictly newer
/// incoming version yields [`Ordering::Less`]. Returns
/// [`VersionError::MalformedVersion`] if either input is not dot-separated
/// ASCII digit segments within [`MAX_SEGMENTS`]. Short versions are compared
/// as if missing trailing segments were zero, so `1.2` equals `1.2.0`.
pub fn compare_versions(installed: &str, incoming: &str) -> Result<Ordering, VersionError> {
    let installed = parse_segments(installed)?;
    let incoming = parse_segments(incoming)?;
    let width = installed.len().max(incoming.len());
    for index in 0..width {
        let left = installed.get(index).copied().unwrap_or(0);
        let right = incoming.get(index).copied().unwrap_or(0);
        match left.cmp(&right) {
            Ordering::Equal => continue,
            other => return Ok(other),
        }
    }
    Ok(Ordering::Equal)
}

/// The P15 install gate: accept `incoming` over `installed` only when it is
/// numerically newer, unless `choice` is [`DowngradeChoice::Allow`].
///
/// Plain function over borrowed `&str`s: the manifest bytes are not owned or
/// parsed here, and the caller keeps its own manifest type.
pub fn check_install(
    installed: &str,
    incoming: &str,
    choice: DowngradeChoice,
) -> Result<(), VersionError> {
    let ordering = compare_versions(installed, incoming)?;
    // `compare_versions` returns installed vs incoming: incoming is strictly
    // newer exactly when the installed version orders Less than incoming.
    if ordering == Ordering::Less {
        return Ok(());
    }
    if choice == DowngradeChoice::Allow {
        return Ok(());
    }
    Err(VersionError::VersionNotNewer)
}

fn parse_segments(version: &str) -> Result<Vec<u64>, VersionError> {
    if version.is_empty() {
        return Err(VersionError::MalformedVersion);
    }
    let mut segments = Vec::new();
    for segment in version.split('.') {
        if segments.len() == MAX_SEGMENTS {
            return Err(VersionError::MalformedVersion);
        }
        if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(VersionError::MalformedVersion);
        }
        let value = segment
            .parse::<u64>()
            .map_err(|_| VersionError::MalformedVersion)?;
        segments.push(value);
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P15: an equal version is refused unless the owner chose a downgrade.
    #[test]
    fn equal_version_is_refused_without_downgrade() {
        let error = check_install("1.2.3", "1.2.3", DowngradeChoice::Refuse).unwrap_err();
        assert_eq!(error.code(), "version_not_newer");
    }

    // P15: a lower version is refused unless the owner chose a downgrade.
    #[test]
    fn lower_version_is_refused_without_downgrade() {
        let error = check_install("2.0.0", "1.9.9", DowngradeChoice::Refuse).unwrap_err();
        assert_eq!(error.code(), "version_not_newer");
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ok(Ordering::Greater));
    }

    // P15: a strictly newer version installs with no downgrade choice.
    #[test]
    fn newer_version_installs_without_downgrade() {
        assert_eq!(
            check_install("1.9.9", "2.0.0", DowngradeChoice::Refuse),
            Ok(())
        );
        assert_eq!(compare_versions("1.9.9", "2.0.0"), Ok(Ordering::Less));
    }

    // P15: comparison is numeric per segment, so 1.10.0 is newer than 1.9.0.
    #[test]
    fn segments_compare_numerically_not_lexically() {
        // installed=1.9.0 orders Less than incoming=1.10.0, i.e. incoming is
        // newer. Textual order would wrongly place 1.10.0 before 1.9.0.
        assert_eq!(
            compare_versions("1.9.0", "1.10.0"),
            Ok(Ordering::Less),
            "numeric per segment: 1.10.0 is newer than 1.9.0"
        );
        assert_eq!(
            check_install("1.9.0", "1.10.0", DowngradeChoice::Refuse),
            Ok(())
        );
    }

    // P15: leading zeros do not make a version newer or newer-looking.
    #[test]
    fn leading_zeros_are_numeric_equality() {
        assert_eq!(compare_versions("1.02", "1.2"), Ok(Ordering::Equal));
        let error = check_install("1.02", "1.2", DowngradeChoice::Refuse).unwrap_err();
        assert_eq!(error.code(), "version_not_newer");
    }

    // P15: missing trailing segments read as zero, so 1.2 equals 1.2.0.
    #[test]
    fn missing_trailing_segments_are_zero() {
        assert_eq!(compare_versions("1.2", "1.2.0"), Ok(Ordering::Equal));
        let error = check_install("1.2.0", "1.2", DowngradeChoice::Refuse).unwrap_err();
        assert_eq!(error.code(), "version_not_newer");
    }

    // P15: the owner-chosen typed downgrade accepts equal and lower versions.
    #[test]
    fn downgrade_choice_accepts_equal_and_lower() {
        assert_eq!(
            check_install("1.2.3", "1.2.3", DowngradeChoice::Allow),
            Ok(())
        );
        assert_eq!(
            check_install("2.0.0", "1.9.9", DowngradeChoice::Allow),
            Ok(())
        );
    }

    // P15: a malformed version is refused and named, never guessed at.
    #[test]
    fn malformed_versions_are_refused() {
        for bad in ["", "1.", ".1", "1..2", "1.2.x", "1.2.-3", " 1.2", "1.2 "] {
            let error = check_install("1.0.0", bad, DowngradeChoice::Refuse).unwrap_err();
            assert_eq!(error.code(), "malformed_version", "input {bad:?}");
        }
        let error = check_install("", "9.9.9", DowngradeChoice::Allow).unwrap_err();
        assert_eq!(error.code(), "malformed_version");
    }

    // P15: a segment that overflows u64 is malformed, not silently wrapped.
    #[test]
    fn overflowing_segment_is_malformed() {
        let error = check_install(
            "1.0.0",
            "99999999999999999999999999",
            DowngradeChoice::Refuse,
        )
        .unwrap_err();
        assert_eq!(error.code(), "malformed_version");
    }

    // P15: more segments than MAX_SEGMENTS is malformed, not prefix-compared.
    #[test]
    fn too_many_segments_is_malformed() {
        let long = "1.2.3.4.5.6.7.8.9";
        let error = check_install("1.0.0", long, DowngradeChoice::Refuse).unwrap_err();
        assert_eq!(error.code(), "malformed_version");
    }

    // P15: the Display line starts with the stable code and carries no host path.
    #[test]
    fn display_leads_with_code_and_has_no_host_path() {
        let error = VersionError::VersionNotNewer;
        let text = error.to_string();
        assert!(text.starts_with("version_not_newer: "), "got {text:?}");
        assert!(!text.contains('/'), "got {text:?}");
    }
}
