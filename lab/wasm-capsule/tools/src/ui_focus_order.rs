//! M2 RA3 (P6): keyboard focus order.
//!
//! The default focus order follows tree order: a depth-first pre-order walk of
//! the focusable nodes. A node may override its position with an explicit
//! `focus_index` in `1..=999`. Nodes that set an index are visited first, in
//! ascending index order (a unique index means no tie is possible); the
//! remaining nodes follow in tree order. Two nodes in the same tree may not
//! share an explicit index, and an index outside the range is refused.
//!
//! Preset bounds chosen here because the task does not give them: the explicit
//! index range is `1..=999`. All work is in memory; nothing here launches,
//! admits or holds a capability, it only orders focus targets for the caller.

use std::fmt;

/// The smallest explicit focus index accepted.
pub const FOCUS_INDEX_MIN: u16 = 1;
/// The largest explicit focus index accepted.
pub const FOCUS_INDEX_MAX: u16 = 999;

/// A refusal from focus-order resolution. One enum, one code per variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusError {
    /// Two nodes set the same explicit focus index.
    FocusIndexDuplicate(u16),
    /// A node set an explicit focus index outside `1..=999`.
    FocusIndexOutOfRange(u16),
}

impl FocusError {
    /// Stable snake_case code for each refusal.
    pub fn code(&self) -> &'static str {
        match self {
            FocusError::FocusIndexDuplicate(_) => "focus_index_duplicate",
            FocusError::FocusIndexOutOfRange(_) => "focus_index_out_of_range",
        }
    }
}

impl fmt::Display for FocusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FocusError::FocusIndexDuplicate(index) => {
                write!(
                    f,
                    "{}: focus index {} is set by more than one node",
                    self.code(),
                    index
                )
            }
            FocusError::FocusIndexOutOfRange(index) => {
                write!(
                    f,
                    "{}: focus index {} is outside 1..=999",
                    self.code(),
                    index
                )
            }
        }
    }
}

/// A focusable node in a focus tree. Children are visited in their stored
/// order, which is the tree order P6 names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusNode {
    /// Stable identity used in the resolved order.
    pub id: String,
    /// Optional explicit focus index in `1..=999`.
    pub focus_index: Option<u16>,
    /// Child nodes, in tree order.
    pub children: Vec<FocusNode>,
}

impl FocusNode {
    /// A leaf node with an optional explicit index.
    pub fn leaf(id: impl Into<String>, focus_index: Option<u16>) -> Self {
        FocusNode {
            id: id.into(),
            focus_index,
            children: Vec::new(),
        }
    }

    /// A node with children and an optional explicit index.
    pub fn with_children(
        id: impl Into<String>,
        focus_index: Option<u16>,
        children: Vec<FocusNode>,
    ) -> Self {
        FocusNode {
            id: id.into(),
            focus_index,
            children,
        }
    }
}

/// Resolve the keyboard focus order of a tree under P6.
///
/// Explicitly indexed nodes come first, ascending by index; the remaining
/// nodes follow in tree order (depth-first pre-order). A duplicate explicit
/// index or an out-of-range index is refused.
pub fn focus_order(root: &FocusNode) -> Result<Vec<String>, FocusError> {
    // Collect pre-order (position, id, index), checking range and duplicates.
    fn walk(
        node: &FocusNode,
        pre: &mut Vec<(usize, String, Option<u16>)>,
    ) -> Result<(), FocusError> {
        if let Some(index) = node.focus_index {
            if !(FOCUS_INDEX_MIN..=FOCUS_INDEX_MAX).contains(&index) {
                return Err(FocusError::FocusIndexOutOfRange(index));
            }
            if pre.iter().any(|(_pos, _id, seen)| *seen == Some(index)) {
                return Err(FocusError::FocusIndexDuplicate(index));
            }
        }
        let position = pre.len();
        pre.push((position, node.id.clone(), node.focus_index));
        for child in &node.children {
            walk(child, pre)?;
        }
        Ok(())
    }

    let mut pre: Vec<(usize, String, Option<u16>)> = Vec::new();
    walk(root, &mut pre)?;

    let mut order: Vec<String> = Vec::with_capacity(pre.len());
    // Indexed nodes first, ascending by unique index.
    for index in FOCUS_INDEX_MIN..=FOCUS_INDEX_MAX {
        for (_pos, id, seen) in &pre {
            if *seen == Some(index) {
                order.push(id.clone());
            }
        }
    }
    // Remaining nodes in tree order.
    for (_pos, id, seen) in &pre {
        if seen.is_none() {
            order.push(id.clone());
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| String::from(*name)).collect()
    }

    // P6: default focus order is tree order.
    #[test]
    fn p6_tree_order_by_default() {
        let tree = FocusNode::with_children(
            "root",
            None,
            vec![
                FocusNode::leaf("a", None),
                FocusNode::with_children("b", None, vec![FocusNode::leaf("b1", None)]),
                FocusNode::leaf("c", None),
            ],
        );
        let order = focus_order(&tree).expect("valid tree");
        assert_eq!(order, ids(&["root", "a", "b", "b1", "c"]));
    }

    // P6: an explicit index moves a node ahead of tree order, ascending.
    #[test]
    fn p6_explicit_index_overrides_tree_order() {
        let tree = FocusNode::with_children(
            "root",
            None,
            vec![FocusNode::leaf("a", Some(2)), FocusNode::leaf("b", Some(1))],
        );
        let order = focus_order(&tree).expect("valid tree");
        assert_eq!(order, ids(&["b", "a", "root"]));
    }

    // P6: unindexed nodes keep tree order after the indexed ones.
    #[test]
    fn p6_unindexed_follow_indexed_in_tree_order() {
        let tree = FocusNode::with_children(
            "root",
            None,
            vec![
                FocusNode::leaf("a", None),
                FocusNode::leaf("b", Some(3)),
                FocusNode::leaf("c", None),
            ],
        );
        let order = focus_order(&tree).expect("valid tree");
        assert_eq!(order, ids(&["b", "root", "a", "c"]));
    }

    // P6: duplicate explicit index is refused.
    #[test]
    fn p6_duplicate_index_refused() {
        let tree = FocusNode::with_children(
            "root",
            None,
            vec![FocusNode::leaf("a", Some(5)), FocusNode::leaf("b", Some(5))],
        );
        let err = focus_order(&tree).expect_err("duplicate index");
        assert_eq!(err.code(), "focus_index_duplicate");
    }

    // P6: out-of-range explicit index is refused.
    #[test]
    fn p6_out_of_range_index_refused() {
        let tree = FocusNode::leaf("a", Some(0));
        let err = focus_order(&tree).expect_err("index zero refused");
        assert_eq!(err.code(), "focus_index_out_of_range");
    }
}
