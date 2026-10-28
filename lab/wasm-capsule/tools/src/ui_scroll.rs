//! A scroll view node (M2 RA3, P6): the smallest model of a scrolling
//! surface with content height, viewport height and a clamped offset.
//!
//! The offset is always in `0..=scrollable()`, where `scrollable()` is
//! `content_height - viewport_height` (zero when content fits). Any request
//! past an edge is clamped, never refused.
//!
//! [`ScrollView::scroll_to_child`] brings a child by id fully into the
//! viewport by computing the smallest offset that reveals it, then clamping
//! that offset to the valid range. An unknown id is refused `unknown_node`.
//!
//! Presets: a fresh view starts at offset 0; a view whose content fits has no
//! scrollable extent and `require_extent` refuses `no_scroll_extent`; child
//! heights below 1 are raised to 1.

use std::fmt;

/// A node inside the scroll view, in content coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// Stable id used by `scroll_to_child`.
    pub id: &'static str,
    /// Distance from the top of the content to the top of the child.
    pub top: u32,
    /// Height of the child in content coordinates, at least 1.
    pub height: u32,
}

impl Child {
    /// Build a child with the given id, top and height. Height is at least 1.
    pub fn new(id: &'static str, top: u32, height: u32) -> Self {
        Self {
            id,
            top,
            height: height.max(1),
        }
    }

    /// The bottom of the child in content coordinates (exclusive).
    pub fn bottom(&self) -> u32 {
        self.top.saturating_add(self.height)
    }
}

/// The scroll view node: content height, viewport height, offset, children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrollView {
    content_height: u32,
    viewport_height: u32,
    offset: u32,
    children: Vec<Child>,
}

/// One refusal from a scroll view operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrollError {
    /// The child id given to `scroll_to_child` is not in the view.
    UnknownNode {
        /// The id that was looked up; no absolute host path.
        id: &'static str,
    },
    /// The view has no scrollable extent because its content fits.
    NoScrollExtent,
}

impl ScrollError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            ScrollError::UnknownNode { .. } => "unknown_node",
            ScrollError::NoScrollExtent => "no_scroll_extent",
        }
    }
}

impl fmt::Display for ScrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            ScrollError::UnknownNode { id } => {
                format!("child id {id} is not in the scroll view")
            }
            ScrollError::NoScrollExtent => {
                "scroll view has no scrollable extent".to_owned()
            }
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for ScrollError {}

impl ScrollView {
    /// Build a view with the given content height and viewport height.
    pub fn new(content_height: u32, viewport_height: u32) -> Self {
        Self {
            content_height,
            viewport_height,
            offset: 0,
            children: Vec::new(),
        }
    }

    /// Add a child to the view.
    pub fn with_child(mut self, child: Child) -> Self {
        self.children.push(child);
        self
    }

    /// The largest possible offset: content minus viewport, or zero.
    pub fn scrollable(&self) -> u32 {
        self.content_height.saturating_sub(self.viewport_height)
    }

    /// Current offset, always within `0..=scrollable()`.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Clamp `raw` into `0..=scrollable()`.
    fn clamp(&self, raw: u32) -> u32 {
        raw.min(self.scrollable())
    }

    /// Set the offset, clamping to the valid range. Returns the offset kept.
    pub fn set_offset(&mut self, raw: u32) -> u32 {
        self.offset = self.clamp(raw);
        self.offset
    }

    /// Scroll by a signed delta, clamping at both edges.
    pub fn scroll_by(&mut self, delta: i64) -> u32 {
        let bounded = (self.offset as i64)
            .saturating_add(delta)
            .clamp(0, self.scrollable() as i64) as u32;
        self.offset = bounded;
        self.offset
    }

    /// Compute the offset that makes `child` fully visible and apply it.
    ///
    /// Refused `unknown_node` when no child carries that id.
    pub fn scroll_to_child(&mut self, id: &'static str) -> Result<u32, ScrollError> {
        let child = self
            .children
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or(ScrollError::UnknownNode { id })?;
        let desired = if child.top < self.offset {
            child.top
        } else if child.bottom() > self.offset.saturating_add(self.viewport_height) {
            child.bottom().saturating_sub(self.viewport_height)
        } else {
            self.offset
        };
        self.offset = self.clamp(desired);
        Ok(self.offset)
    }

    /// Refuse `no_scroll_extent` when the view cannot scroll at all.
    pub fn require_extent(&self) -> Result<u32, ScrollError> {
        if self.scrollable() == 0 {
            Err(ScrollError::NoScrollExtent)
        } else {
            Ok(self.scrollable())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: offset is clamped to 0..=(content - viewport); overscroll never
    // exceeds the scrollable range.
    #[test]
    fn p6_offset_clamps_to_bounds() {
        let mut view = ScrollView::new(1000, 400);
        assert_eq!(view.scrollable(), 600);
        assert_eq!(view.set_offset(9999), 600);
        assert_eq!(view.set_offset(0), 0);
        assert_eq!(view.scroll_by(-50), 0);
        assert_eq!(view.scroll_by(10_000), 600);
        assert_eq!(view.scroll_by(-10_000), 0);
    }

    // P6: content that fits yields zero extent and no offset movement.
    #[test]
    fn p6_content_fitting_has_zero_extent() {
        let view = ScrollView::new(300, 400);
        assert_eq!(view.scrollable(), 0);
        let mut view = view;
        assert_eq!(view.set_offset(123), 0);
        assert_eq!(view.scroll_by(500), 0);
        assert_eq!(view.require_extent().unwrap_err().code(), "no_scroll_extent");
        assert!(ScrollView::new(500, 300).require_extent().is_ok());
    }

    // P6: scroll-to-child computes the offset that fully reveals the child,
    // per rule: bottom - viewport when below, top when above, clamped.
    #[test]
    fn p6_scroll_to_child_computes_offset() {
        let mut view = ScrollView::new(1000, 300)
            .with_child(Child::new("top", 0, 50))
            .with_child(Child::new("mid", 500, 100))
            .with_child(Child::new("tail", 950, 50));
        assert_eq!(view.scrollable(), 700);

        // Child below the viewport: its bottom reaches the viewport bottom.
        assert_eq!(view.scroll_to_child("mid").unwrap(), 300);
        assert_eq!(view.offset(), 300);

        // Child above the current offset: scroll up exactly to its top.
        assert_eq!(view.scroll_to_child("top").unwrap(), 0);
        assert_eq!(view.offset(), 0);

        // Child at the very bottom: bottom(1000) minus viewport(300) = 700,
        // which equals scrollable() and stays within the clamped range.
        assert_eq!(view.scroll_to_child("tail").unwrap(), 700);
        assert_eq!(view.offset(), 700);
    }

    // P6: an already visible child does not move the offset.
    #[test]
    fn p6_scroll_to_visible_child_keeps_offset() {
        let mut view = ScrollView::new(1000, 400).with_child(Child::new("mid", 100, 50));
        view.set_offset(100);
        assert_eq!(view.scroll_to_child("mid").unwrap(), 100);
    }

    // P6: an unknown child id is refused with the stable code, and the
    // Display carries that code without any absolute host path.
    #[test]
    fn p6_unknown_child_is_refused() {
        let mut view = ScrollView::new(1000, 400);
        let err = view.scroll_to_child("ghost").unwrap_err();
        assert_eq!(err.code(), "unknown_node");
        let text = err.to_string();
        assert!(text.starts_with("unknown_node: "));
        assert!(!text.contains('/'));
        assert_eq!(view.offset(), 0);
    }
}
