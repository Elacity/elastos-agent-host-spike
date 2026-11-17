//! `ui_focus_trap`: keyboard focus containment for a dialog (M2 RA3, P6).
//!
//! While a dialog is open, Tab and Shift+Tab move focus only among the
//! dialog's focusable nodes and wrap around at both ends. Closing the dialog
//! returns focus to the node that opened it, provided that node is still
//! present and focusable on the restored surface, and otherwise to the first
//! focusable node of the restored surface.
//!
//! The types here are self-contained: they model node identity, the set of
//! focusable nodes inside a dialog, the opener that must regain focus, and
//! the surface restored on close. Focus changes are plain data transitions;
//! resolving them to a Runtime capability request is the caller's job, never
//! this module's.
//!
//! Preset values (chosen small and conservative, P6):
//! - a dialog is considered open only when it was opened with at least one
//!   focusable node; an empty dialog is refused with `empty_dialog`;
//! - a node id is any `u32` label supplied by the caller;
//! - unknown node ids are refused with `unknown_node`;
//! - tabbing with no focusable node is refused with `no_focusable_node`;
//! - on close, the opener is honoured only if it appears in the restored
//!   surface and is focusable there; a missing opener falls back.
//!
//! [`FocusError`] is the one error enum; [`FocusError::code`] returns stable
//! snake_case codes and `Display` renders `<code>: <explanation>`.

use std::fmt;

/// Stable refusal codes for focus-trap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusError {
    /// A dialog was opened with no focusable node.
    EmptyDialog,
    /// A node id was referenced that the trap does not know.
    UnknownNode,
    /// A tab movement, or a close, had no focusable target.
    NoFocusableNode,
}

impl FocusError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            FocusError::EmptyDialog => "empty_dialog",
            FocusError::UnknownNode => "unknown_node",
            FocusError::NoFocusableNode => "no_focusable_node",
        }
    }
}

impl fmt::Display for FocusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            FocusError::EmptyDialog => "a dialog must contain at least one focusable node",
            FocusError::UnknownNode => "the referenced node is not known to this focus trap",
            FocusError::NoFocusableNode => "there is no focusable node to move to",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for FocusError {}

/// A focusable node identified by a caller-supplied label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusNode {
    id: u32,
    focusable: bool,
}

impl FocusNode {
    /// A focusable node with the given id.
    pub fn new(id: u32) -> Self {
        FocusNode {
            id,
            focusable: true,
        }
    }

    /// A node that exists but cannot receive focus.
    pub fn unfocusable(id: u32) -> Self {
        FocusNode {
            id,
            focusable: false,
        }
    }

    /// The node's id.
    pub fn id(self) -> u32 {
        self.id
    }

    /// Whether this node can receive focus.
    pub fn is_focusable(self) -> bool {
        self.focusable
    }
}

/// An open dialog: its focusable nodes in tab order and the node that
/// opened it (the opener may be absent).
#[derive(Debug, Clone)]
pub struct Dialog {
    nodes: Vec<FocusNode>,
    opener: Option<FocusNode>,
    focused: usize,
}

impl Dialog {
    /// Open a dialog over `nodes` (tab order) from `opener`.
    ///
    /// Only focusable nodes are kept; if none remain the dialog is refused
    /// with [`FocusError::EmptyDialog`]. Focus starts on the first node.
    pub fn open(nodes: Vec<FocusNode>, opener: Option<FocusNode>) -> Result<Self, FocusError> {
        let nodes: Vec<FocusNode> = nodes.into_iter().filter(|n| n.is_focusable()).collect();
        if nodes.is_empty() {
            return Err(FocusError::EmptyDialog);
        }
        Ok(Dialog {
            nodes,
            opener,
            focused: 0,
        })
    }

    /// The node that currently holds focus.
    pub fn focused(&self) -> FocusNode {
        self.nodes[self.focused]
    }

    /// The opener recorded at open time, if any.
    pub fn opener(&self) -> Option<FocusNode> {
        self.opener
    }

    /// Move focus forward, wrapping from the last node to the first.
    pub fn tab(&mut self) -> Result<FocusNode, FocusError> {
        self.step(1)
    }

    /// Move focus backward, wrapping from the first node to the last.
    pub fn shift_tab(&mut self) -> Result<FocusNode, FocusError> {
        self.step(-1)
    }

    fn step(&mut self, delta: isize) -> Result<FocusNode, FocusError> {
        if self.nodes.is_empty() {
            return Err(FocusError::NoFocusableNode);
        }
        let len = self.nodes.len() as isize;
        let next = (self.focused as isize + delta).rem_euclid(len);
        self.focused = next as usize;
        Ok(self.nodes[self.focused])
    }

    /// Focus a specific node id inside the dialog.
    pub fn focus(&mut self, id: u32) -> Result<FocusNode, FocusError> {
        let idx = self
            .nodes
            .iter()
            .position(|n| n.id() == id)
            .ok_or(FocusError::UnknownNode)?;
        self.focused = idx;
        Ok(self.nodes[idx])
    }

    /// Close the dialog and decide where focus returns.
    ///
    /// Returns the opener when that node is present in `restored` and
    /// focusable there; otherwise the first focusable node of `restored`;
    /// otherwise [`FocusError::NoFocusableNode`].
    pub fn close(self, restored: &[FocusNode]) -> Result<FocusNode, FocusError> {
        if let Some(opener) = self.opener {
            if let Some(node) = restored
                .iter()
                .find(|n| n.id() == opener.id() && n.is_focusable())
            {
                return Ok(*node);
            }
        }
        restored
            .iter()
            .copied()
            .find(|n| n.is_focusable())
            .ok_or(FocusError::NoFocusableNode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(ids: &[u32]) -> Vec<FocusNode> {
        ids.iter().copied().map(FocusNode::new).collect()
    }

    // P6: keyboard focus stays within the dialog and wraps forward.
    #[test]
    fn tab_wraps_within_dialog() {
        let mut d = Dialog::open(nodes(&[1, 2, 3]), None).expect("dialog opens");
        assert_eq!(d.focused().id(), 1);
        assert_eq!(d.tab().expect("tab").id(), 2);
        assert_eq!(d.tab().expect("tab").id(), 3);
        assert_eq!(d.tab().expect("wrap to first").id(), 1);
    }

    // P6: Shift+Tab wraps backward from the first node to the last.
    #[test]
    fn shift_tab_wraps_within_dialog() {
        let mut d = Dialog::open(nodes(&[1, 2, 3]), None).expect("dialog opens");
        assert_eq!(d.shift_tab().expect("shift tab wraps").id(), 3);
        assert_eq!(d.shift_tab().expect("shift tab").id(), 2);
    }

    // P6: nodes that cannot receive focus are never visited.
    #[test]
    fn unfocusable_nodes_are_skipped() {
        let all = vec![
            FocusNode::new(1),
            FocusNode::unfocusable(2),
            FocusNode::new(3),
        ];
        let mut d = Dialog::open(all, None).expect("dialog opens");
        assert_eq!(d.tab().expect("tab").id(), 3);
        assert_eq!(d.tab().expect("wrap").id(), 1);
    }

    // P6: closing returns focus to the opener node when it is still present.
    #[test]
    fn close_restores_opener() {
        let opener = FocusNode::new(10);
        let d = Dialog::open(nodes(&[1, 2]), Some(opener)).expect("dialog opens");
        let restored = nodes(&[10, 11]);
        assert_eq!(d.close(&restored).expect("restore").id(), 10);
    }

    // P6: if the opener is gone from the restored surface, focus goes to
    // the first focusable node there, not to the vanished opener.
    #[test]
    fn close_restores_first_when_opener_gone() {
        let opener = FocusNode::new(10);
        let d = Dialog::open(nodes(&[1, 2]), Some(opener)).expect("dialog opens");
        let restored = nodes(&[11, 12]);
        assert_eq!(d.close(&restored).expect("restore").id(), 11);
    }

    // P6: an opener that is no longer focusable falls back to first node.
    #[test]
    fn close_skips_unfocusable_opener() {
        let opener = FocusNode::unfocusable(10);
        let d = Dialog::open(nodes(&[1]), Some(opener)).expect("dialog opens");
        let restored = vec![FocusNode::unfocusable(9), FocusNode::new(12)];
        assert_eq!(d.close(&restored).expect("restore").id(), 12);
    }

    // P6: an opener present but unfocusable on the restored surface is
    // skipped in favour of the first focusable node.
    #[test]
    fn close_falls_back_when_opener_unfocusable_on_surface() {
        let opener = FocusNode::new(10);
        let d = Dialog::open(nodes(&[1]), Some(opener)).expect("dialog opens");
        let restored = vec![FocusNode::unfocusable(10), FocusNode::new(13)];
        assert_eq!(d.close(&restored).expect("restore").id(), 13);
    }

    // P6: an empty dialog is refused with a stable code.
    #[test]
    fn empty_dialog_refused() {
        let err = Dialog::open(Vec::new(), None).expect_err("empty refused");
        assert_eq!(err.code(), "empty_dialog");
        assert_eq!(
            err.to_string(),
            "empty_dialog: a dialog must contain at least one focusable node"
        );
    }

    // P6: a dialog containing only unfocusable nodes is empty.
    #[test]
    fn only_unfocusable_is_empty_dialog() {
        let err = Dialog::open(vec![FocusNode::unfocusable(1)], None)
            .expect_err("all unfocusable refused");
        assert_eq!(err.code(), "empty_dialog");
    }

    // P6: focusing an unknown node is refused with a stable code.
    #[test]
    fn unknown_node_refused() {
        let mut d = Dialog::open(nodes(&[1, 2]), None).expect("dialog opens");
        let err = d.focus(99).expect_err("unknown refused");
        assert_eq!(err.code(), "unknown_node");
    }

    // P6: wrapping still lands on the last node in a single node dialog.
    #[test]
    fn single_node_wraps_to_itself() {
        let mut d = Dialog::open(nodes(&[7]), None).expect("dialog opens");
        assert_eq!(d.tab().expect("tab").id(), 7);
        assert_eq!(d.shift_tab().expect("shift tab").id(), 7);
    }

    // P6: closing with no opener and no focusable restored node is refused.
    #[test]
    fn close_without_target_refused() {
        let d = Dialog::open(nodes(&[1]), None).expect("dialog opens");
        let err = d
            .close(&[FocusNode::unfocusable(5)])
            .expect_err("nothing to restore");
        assert_eq!(err.code(), "no_focusable_node");
    }
}
