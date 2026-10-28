//! RA3 (P6) toast notification queue. Notifications are a UI surface: a
//! capsule asks to post a toast, and the queue decides when it is shown.
//! This module is self-contained host tooling and makes no Runtime
//! admission or launch decision.
//!
//! Rules:
//! - at most 3 toasts are visible at one time; further accepted toasts wait
//!   in FIFO order and are promoted when a visible toast expires;
//! - every toast has a duration between 1 and 10 whole seconds inclusive;
//! - a capsule may post at most 5 toasts in any rolling 60 second window.
//!
//! Time is never read from the host. Callers pass an injected clock value
//! (milliseconds) to every operation, and expiry is evaluated against it.
//!
//! Preset values chosen here because the task did not give them: the window
//! is exactly 60_000 ms and a toast accepted at `t` still counts while
//! `now - t < 60_000`; a rate-limited post consumes no slot and no id; a
//! promoted toast starts a fresh duration at the promotion clock.

use std::collections::VecDeque;
use std::fmt;

/// The maximum number of toasts visible at one time.
pub const MAX_VISIBLE: usize = 3;
/// The shortest accepted toast duration, in milliseconds.
pub const MIN_DURATION_MS: u64 = 1_000;
/// The longest accepted toast duration, in milliseconds.
pub const MAX_DURATION_MS: u64 = 10_000;
/// The rate limit window, in milliseconds.
pub const RATE_WINDOW_MS: u64 = 60_000;
/// The maximum number of accepted posts inside one window.
pub const MAX_POSTS_PER_WINDOW: usize = 5;

/// A refusal from the toast queue. Display renders `<code>: <explanation>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastError {
    /// The requested duration is outside 1 to 10 seconds.
    BadToastDuration,
    /// The capsule posted more than 5 toasts inside one minute.
    ToastRateLimited,
}

impl ToastError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            ToastError::BadToastDuration => "bad_toast_duration",
            ToastError::ToastRateLimited => "toast_rate_limited",
        }
    }
}

impl fmt::Display for ToastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            ToastError::BadToastDuration => {
                "toast duration must be between 1 and 10 whole seconds"
            }
            ToastError::ToastRateLimited => "capsule posted more than 5 toasts in one minute",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for ToastError {}

/// A toast that has been accepted by the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    id: u64,
    capsule: String,
    text: String,
    duration_ms: u64,
}

impl Toast {
    /// Queue-assigned identity, unique within one queue.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// The capsule that posted this toast.
    pub fn capsule(&self) -> &str {
        &self.capsule
    }
    /// The toast message body.
    pub fn text(&self) -> &str {
        &self.text
    }
    /// The accepted duration in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

#[derive(Debug, Clone)]
struct Visible {
    toast: Toast,
    shown_at_ms: u64,
}

/// A per-capsule FIFO queue of toasts with a bounded visible set.
#[derive(Debug, Default)]
pub struct ToastQueue {
    next_id: u64,
    visible: VecDeque<Visible>,
    waiting: VecDeque<Toast>,
    accepted_at_ms: VecDeque<u64>,
}

impl ToastQueue {
    /// A new empty queue.
    pub fn new() -> Self {
        ToastQueue::default()
    }
    /// Toasts currently visible, oldest first.
    pub fn visible(&self) -> impl Iterator<Item = &Toast> {
        self.visible.iter().map(|v| &v.toast)
    }
    /// Toasts accepted but still waiting, FIFO order.
    pub fn waiting(&self) -> impl Iterator<Item = &Toast> {
        self.waiting.iter()
    }
    /// Number of toasts visible right now.
    pub fn visible_count(&self) -> usize {
        self.visible.len()
    }
    /// Number of toasts waiting right now.
    pub fn waiting_count(&self) -> usize {
        self.waiting.len()
    }
    /// Validate a duration: between 1 and 10 whole seconds inclusive.
    pub fn check_duration(duration_ms: u64) -> Result<(), ToastError> {
        if (MIN_DURATION_MS..=MAX_DURATION_MS).contains(&duration_ms) {
            Ok(())
        } else {
            Err(ToastError::BadToastDuration)
        }
    }

    /// Post a toast from `capsule` at clock value `now_ms`.
    ///
    /// The duration is checked first (a bad duration never consumes a rate
    /// slot). Expired visible toasts are then dropped and waiting toasts are
    /// promoted at `now_ms`, so the answer reflects the queue at `now_ms`.
    /// Only then is the rolling window pruned and the rate checked. A
    /// rate-limited post is refused and consumes no slot and no id.
    pub fn post(
        &mut self,
        capsule: &str,
        text: &str,
        duration_ms: u64,
        now_ms: u64,
    ) -> Result<u64, ToastError> {
        Self::check_duration(duration_ms)?;
        self.expire(now_ms);
        self.prune_window(now_ms);
        if self.accepted_at_ms.len() >= MAX_POSTS_PER_WINDOW {
            return Err(ToastError::ToastRateLimited);
        }
        self.accepted_at_ms.push_back(now_ms);

        let id = self.next_id;
        self.next_id += 1;
        let toast = Toast {
            id,
            capsule: capsule.to_string(),
            text: text.to_string(),
            duration_ms,
        };
        if self.visible.len() < MAX_VISIBLE {
            self.visible.push_back(Visible {
                toast,
                shown_at_ms: now_ms,
            });
        } else {
            self.waiting.push_back(toast);
        }
        self.promote(now_ms);
        Ok(id)
    }

    /// Advance the queue to clock value `now_ms`: drop expired visible toasts
    /// and promote waiting toasts in FIFO order, each starting at `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        self.visible
            .retain(|v| now_ms < v.shown_at_ms.saturating_add(v.toast.duration_ms));
        self.promote(now_ms);
    }

    fn promote(&mut self, now_ms: u64) {
        while self.visible.len() < MAX_VISIBLE {
            match self.waiting.pop_front() {
                Some(toast) => self.visible.push_back(Visible {
                    toast,
                    shown_at_ms: now_ms,
                }),
                None => break,
            }
        }
    }

    fn prune_window(&mut self, now_ms: u64) {
        // Strictly rolling: a post at `t` is inside the window while
        // `now - t < RATE_WINDOW_MS`, and outside once it reaches the window.
        while let Some(&at) = self.accepted_at_ms.front() {
            if now_ms.saturating_sub(at) < RATE_WINDOW_MS {
                break;
            }
            self.accepted_at_ms.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: at most three toasts are visible; the fourth waits FIFO and is
    // shown only once an earlier toast expires.
    #[test]
    fn fourth_toast_waits_then_is_promoted_fifo() {
        let mut q = ToastQueue::new();
        for i in 0..4u64 {
            q.post("cap-a", &format!("t{i}"), 2_000, 0).unwrap();
        }
        assert_eq!(q.visible_count(), 3);
        assert_eq!(q.waiting_count(), 1);
        let shown: Vec<&str> = q.visible().map(|t| t.text()).collect();
        assert_eq!(shown, vec!["t0", "t1", "t2"]);
        let waiting: Vec<&str> = q.waiting().map(|t| t.text()).collect();
        assert_eq!(waiting, vec!["t3"]);

        // All three visible toasts were shown at 0 with duration 2_000, so at
        // 2_000 all expire together and only the waiting toast is promoted.
        q.expire(2_000);
        assert_eq!(q.visible_count(), 1);
        assert_eq!(q.waiting_count(), 0);
        let shown: Vec<&str> = q.visible().map(|t| t.text()).collect();
        assert_eq!(shown, vec!["t3"]);
    }

    // P6: accepted durations are 1 to 10 seconds; anything else is refused
    // with bad_toast_duration.
    #[test]
    fn duration_bounds_are_refused_with_code() {
        assert_eq!(
            ToastQueue::check_duration(999).unwrap_err().code(),
            "bad_toast_duration"
        );
        assert_eq!(
            ToastQueue::check_duration(10_001).unwrap_err().code(),
            "bad_toast_duration"
        );
        assert!(ToastQueue::check_duration(1_000).is_ok());
        assert!(ToastQueue::check_duration(10_000).is_ok());

        let mut q = ToastQueue::new();
        assert_eq!(
            q.post("cap-a", "short", 0, 0).unwrap_err().code(),
            "bad_toast_duration"
        );
        assert_eq!(q.visible_count(), 0);
    }

    // P6: a bad duration does not consume the once-a-minute rate slot.
    #[test]
    fn bad_duration_does_not_consume_rate_slot() {
        let mut q = ToastQueue::new();
        for _ in 0..5 {
            assert!(q.post("cap-a", "ok", 1_000, 0).is_ok());
        }
        assert_eq!(
            q.post("cap-a", "bad", 500, 0).unwrap_err().code(),
            "bad_toast_duration"
        );
        assert_eq!(
            q.post("cap-a", "ok", 1_000, 0).unwrap_err().code(),
            "toast_rate_limited"
        );
    }

    // P6: the sixth post inside one minute is refused with
    // toast_rate_limited and adds no toast.
    #[test]
    fn sixth_post_in_a_minute_is_rate_limited() {
        let mut q = ToastQueue::new();
        for _ in 0..5 {
            q.post("cap-a", "ok", 1_000, 1_000).unwrap();
        }
        assert_eq!(
            q.post("cap-a", "extra", 1_000, 1_000).unwrap_err().code(),
            "toast_rate_limited"
        );
        assert_eq!(q.visible_count(), 3);
        assert_eq!(q.waiting_count(), 2);
    }

    // P6: once the full window has elapsed since the last accepted post, a
    // new post is accepted again.
    #[test]
    fn rate_limit_clears_after_a_minute() {
        let mut q = ToastQueue::new();
        for _ in 0..5 {
            q.post("cap-a", "ok", 1_000, 0).unwrap();
        }
        assert_eq!(
            q.post("cap-a", "ok", 1_000, 0).unwrap_err().code(),
            "toast_rate_limited"
        );
        // At exactly the window edge the earlier posts are outside it.
        let later = RATE_WINDOW_MS;
        assert!(q.post("cap-a", "again", 1_000, later).is_ok());
    }

    // P6: a visible toast is gone exactly when its duration has elapsed.
    #[test]
    fn toast_expires_at_its_duration() {
        let mut q = ToastQueue::new();
        q.post("cap-a", "hello", 3_000, 100).unwrap();
        q.expire(3_099);
        assert_eq!(q.visible_count(), 1);
        q.expire(3_100);
        assert_eq!(q.visible_count(), 0);
    }

    // P6: a promoted toast gets its own full duration from the promotion
    // clock, not from its post time.
    #[test]
    fn promoted_toast_gets_full_duration_from_promotion() {
        let mut q = ToastQueue::new();
        for i in 0..4u64 {
            q.post("cap-a", &format!("t{i}"), 2_000, 0).unwrap();
        }
        q.expire(2_000);
        assert_eq!(q.visible_count(), 1);
        q.expire(3_999);
        assert_eq!(q.visible_count(), 1);
        q.expire(4_000);
        assert_eq!(q.visible_count(), 0);
    }
}
