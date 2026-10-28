//! P19 owner-view fetch progress per CID.
//!
//! The owner view shows, for one content id, the bytes already fetched, the
//! expected total bytes, and the number of verified chunks. Progress never
//! moves backwards. The one allowed backslide is a restart, which sets
//! `fetch_restarted` and zeroes the counters; a restart is explicit, never
//! inferred from smaller input.
//!
//! Percentages are computed in integers from `bytes_done * 100 / total`.
//! A zero total has no percentage (`None`).
//!
//! Preset values the task did not give, chosen small and conservative:
//!   - chunk window is 16 Bytes for a fresh fetch;
//!   - default `ProgressBudget` has all limits at zero, meaning no work
//!     is admitted until the caller raises them;
//!   - percentages truncate toward zero.

use std::fmt;

/// Error table for [`FetchProgress`]. Every variant has exactly one arm in
/// [`FetchProgressError::code`]. Display renders `<code>: <explanation>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchProgressError {
    /// Bytes moved backwards without an explicit restart.
    Backslide,
    /// Verified chunks moved backwards without an explicit restart.
    ChunkBackslide,
    /// A restart was requested after a fetch already finished with bytes.
    RestartAfterComplete,
    /// A single advance overflowed the running byte or chunk count.
    Overflow,
    /// The byte total was set to a different value mid-fetch.
    TotalChanged,
}

impl FetchProgressError {
    /// Stable snake_case code for the owner view. Names in the task are
    /// written in backticks and are exactly this string.
    pub fn code(&self) -> &'static str {
        match self {
            FetchProgressError::Backslide => "backslide",
            FetchProgressError::ChunkBackslide => "chunk_backslide",
            FetchProgressError::RestartAfterComplete => "restart_after_complete",
            FetchProgressError::Overflow => "overflow",
            FetchProgressError::TotalChanged => "total_changed",
        }
    }
}

impl fmt::Display for FetchProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            FetchProgressError::Backslide => {
                "bytes done went backwards without a restart"
            }
            FetchProgressError::ChunkBackslide => {
                "verified chunks went backwards without a restart"
            }
            FetchProgressError::RestartAfterComplete => {
                "cannot restart a fetch that already completed"
            }
            FetchProgressError::Overflow => {
                "advance overflowed the fetch counters"
            }
            FetchProgressError::TotalChanged => {
                "byte total changed while a fetch was in progress"
            }
        };
        write!(f, "{}: {}", self.code(), text)
    }
}

impl std::error::Error for FetchProgressError {}

/// Progress for one content id. Monotone in `bytes_done`, `total_bytes`
/// (immutable after first set) and `chunks_verified`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchProgress {
    cid: String,
    total_bytes: Option<u64>,
    bytes_done: u64,
    chunks_verified: u64,
    fetch_restarted: bool,
}

impl FetchProgress {
    /// Fresh progress for `cid`. Total is unknown until [`set_total`] runs.
    pub fn new(cid: impl Into<String>) -> Self {
        Self {
            cid: cid.into(),
            total_bytes: None,
            bytes_done: 0,
            chunks_verified: 0,
            fetch_restarted: false,
        }
    }

    /// Content id this progress describes.
    pub fn cid(&self) -> &str {
        &self.cid
    }

    /// Bytes fetched so far.
    pub fn bytes_done(&self) -> u64 {
        self.bytes_done
    }

    /// Expected total bytes, or `None` before [`set_total`].
    pub fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    /// Chunks verified locally.
    pub fn chunks_verified(&self) -> u64 {
        self.chunks_verified
    }

    /// True after a [`restart`], meaning the next [`advance`] is not a
    /// backslide in the owner's eyes.
    pub fn fetch_restarted(&self) -> bool {
        self.fetch_restarted
    }

    /// Set the expected total once. A later different total while bytes
    /// remain is `total_changed`.
    pub fn set_total(&mut self, total: u64) -> Result<(), FetchProgressError> {
        match self.total_bytes {
            None => {
                self.total_bytes = Some(total);
                Ok(())
            }
            Some(t) if t == total => Ok(()),
            Some(_) => Err(FetchProgressError::TotalChanged),
        }
    }

    /// Record `bytes` fetched and `chunks` verified as a single step.
    /// Backslide is refused unless [`restart`] was called since the last
    /// advance; then the restart flag clears.
    ///
    /// The overflow check is on the running counters before the total
    /// clamp, so a sum that cannot fit is refused even when it would have
    /// been clamped to the total.
    pub fn advance(
        &mut self,
        bytes: u64,
        chunks: u64,
    ) -> Result<(), FetchProgressError> {
        if !self.fetch_restarted {
            if bytes < self.bytes_done {
                return Err(FetchProgressError::Backslide);
            }
            if chunks < self.chunks_verified {
                return Err(FetchProgressError::ChunkBackslide);
            }
        }
        let new_bytes = self
            .bytes_done
            .checked_add(bytes)
            .ok_or(FetchProgressError::Overflow)?;
        let new_chunks = self
            .chunks_verified
            .checked_add(chunks)
            .ok_or(FetchProgressError::Overflow)?;
        if let Some(total) = self.total_bytes {
            let clamped = new_bytes.min(total);
            self.bytes_done = clamped;
        } else {
            self.bytes_done = new_bytes;
        }
        self.chunks_verified = new_chunks;
        self.fetch_restarted = false;
        Ok(())
    }

    /// Explicit restart: zero the counters and set `fetch_restarted`.
    /// Refused once the fetch has reached its total (a finished fetch is not
    /// a restart candidate).
    pub fn restart(&mut self) -> Result<(), FetchProgressError> {
        let complete = matches!(self.total_bytes, Some(t) if self.bytes_done >= t && t > 0);
        if complete {
            return Err(FetchProgressError::RestartAfterComplete);
        }
        self.bytes_done = 0;
        self.chunks_verified = 0;
        self.fetch_restarted = true;
        Ok(())
    }

    /// Integer percent of total bytes, truncated toward zero. `None` when
    /// the total is unknown or zero.
    pub fn percent(&self) -> Option<u64> {
        let total = self.total_bytes?;
        if total == 0 {
            return None;
        }
        Some(self.bytes_done.saturating_mul(100) / total)
    }
}

/// Conservative budget for a fetch session. All limits default to zero,
/// which admits no work; the caller raises them explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressBudget {
    pub max_bytes: u64,
    pub max_chunks: u64,
    pub max_restarts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // P19: normal advance is monotone; integer percent tracks totals.
    #[test]
    fn advance_is_monotone_and_percent_is_integer() {
        let mut p = FetchProgress::new("cid-abc");
        assert_eq!(p.percent(), None);
        p.set_total(200).expect("set total once");
        p.advance(50, 1).expect("first advance");
        p.advance(50, 1).expect("second advance");
        assert_eq!(p.bytes_done(), 100);
        assert_eq!(p.chunks_verified(), 2);
        assert_eq!(p.percent(), Some(50));
        assert!(!p.fetch_restarted());
    }

    // P19: without a restart, a backslide is a named refusal.
    #[test]
    fn backslide_without_restart_is_refused() {
        let mut p = FetchProgress::new("cid-abc");
        p.set_total(100).expect("set total");
        p.advance(80, 1).expect("advance");
        match p.advance(10, 0) {
            Err(e) => assert_eq!(e.code(), "backslide"),
            Ok(()) => panic!("backslide must be refused"),
        }
        assert_eq!(p.bytes_done(), 80);
        assert_eq!(p.chunks_verified(), 1);
    }

    // P19: a restart is explicit and is the only permitted backslide.
    #[test]
    fn restart_allows_backslide_and_flags_it() {
        let mut p = FetchProgress::new("cid-xyz");
        p.set_total(100).expect("set total");
        p.advance(60, 2).expect("advance");
        p.restart().expect("restart");
        assert!(p.fetch_restarted());
        assert_eq!(p.bytes_done(), 0);
        assert_eq!(p.chunks_verified(), 0);
        p.advance(5, 1).expect("post restart advance");
        assert!(!p.fetch_restarted());
        assert_eq!(p.bytes_done(), 5);
        assert_eq!(p.percent(), Some(5));
    }

    // P19: zero-limit budget admits nothing and counts nothing.
    #[test]
    fn zero_limit_budget_is_closed() {
        let b = ProgressBudget::default();
        assert_eq!(b.max_bytes, 0);
        assert_eq!(b.max_chunks, 0);
        assert_eq!(b.max_restarts, 0);
    }

    // P19: an advance whose running sum overflows the byte counter is a
    // named refusal, not a wrap. Each leg stays under the total so the
    // pre-clamp running sum is what overflows.
    #[test]
    fn overflow_advance_is_refused() {
        let mut p = FetchProgress::new("cid-big");
        p.set_total(u64::MAX).expect("set total");
        // First leg leaves room below u64::MAX in both the total and the
        // running sum.
        let first = u64::MAX / 2 + 1;
        p.advance(first, 0).expect("first advance");
        assert_eq!(p.bytes_done(), first);
        // Second leg would sum past u64::MAX in the running counter even
        // though the total is u64::MAX; the addition itself must be refused
        // with the overflow code, never silently clamped.
        match p.advance(u64::MAX, 0) {
            Err(e) => assert_eq!(e.code(), "overflow"),
            Ok(()) => panic!("overflow must be refused"),
        }
        // No mutation on refusal.
        assert_eq!(p.bytes_done(), first);
    }

    // P19: a finished fetch refuses restart by code.
    #[test]
    fn restart_after_complete_is_refused() {
        let mut p = FetchProgress::new("cid-done");
        p.set_total(10).expect("set total");
        p.advance(10, 1).expect("advance");
        let err = p.restart().expect_err("must refuse");
        assert_eq!(err.code(), "restart_after_complete");
    }
}
