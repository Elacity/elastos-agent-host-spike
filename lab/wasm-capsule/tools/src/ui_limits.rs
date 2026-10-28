//! Host-configurable limits on a capsule's UI tree (M2 RA3, P6, P10).
//!
//! A capsule may describe a UI tree, and the host bounds how large that tree
//! may be before anything else looks at it. This module adds no policy of its
//! own: the three limits come from host config through [`UiLimits`], and the
//! only check here is [`UiLimits::check`], which refuses a tree that exceeds
//! any limit with [`UiLimitError::UiTreeTooLarge`] naming the exceeded limit.
//!
//! The three limits are:
//! - `max_nodes`: the number of nodes in the tree.
//! - `max_depth`: the depth of the deepest node, the root being depth 1.
//! - `max_text_bytes`: the total bytes of all node text, summed over nodes.
//!
//! Preset values the task does not give: callers build [`UiLimits`] from their
//! own host config. For tests only, [`UiLimits::small_preset`] is a small,
//! conservative set (64 nodes, depth 8, 4096 text bytes) stated here so the
//! numbers live in one place.
//!
//! A limit of zero refuses any tree that has more than zero of what that limit
//! counts. Because every limit is inclusive (a value equal to the limit is
//! accepted), a zero node limit or a zero depth limit refuses every non-empty
//! tree, since every non-empty tree has at least one node and depth at least 1.
//! The empty tree has zero nodes, depth 0 and no text, so it fits zero node and
//! zero depth limits; only a zero text limit refuses it, and only if it carries
//! text. Zeroing all three limits therefore refuses every non-empty tree.
//!
//! Refusals name the limit that was exceeded (a relative name such as
//! `max_nodes`), never an absolute host path.

use core::fmt;

/// A single limit that a capsule's UI tree may exceed. The name is a stable,
/// relative identifier used in refusals and in messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitName {
    /// The maximum number of nodes.
    MaxNodes,
    /// The maximum depth, the root being depth 1.
    MaxDepth,
    /// The maximum total text bytes.
    MaxTextBytes,
}

impl LimitName {
    /// The relative name of this limit, as written in a refusal.
    pub fn as_str(self) -> &'static str {
        match self {
            LimitName::MaxNodes => "max_nodes",
            LimitName::MaxDepth => "max_depth",
            LimitName::MaxTextBytes => "max_text_bytes",
        }
    }
}

impl fmt::Display for LimitName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The reason a UI tree was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiLimitError {
    /// The tree exceeded the named limit. `limit` is the configured value and
    /// `observed` is the tree's value, so the refusal names which limit and by
    /// how much.
    UiTreeTooLarge {
        /// Which limit was exceeded.
        which: LimitName,
        /// The configured limit.
        limit: u64,
        /// The tree's observed value for that limit.
        observed: u64,
    },
}

impl UiLimitError {
    /// The stable snake_case code for this refusal. Tests assert this, never
    /// the Display text.
    pub fn code(&self) -> &'static str {
        match self {
            UiLimitError::UiTreeTooLarge { .. } => "ui_tree_too_large",
        }
    }

    /// The limit that was exceeded, if this refusal names one.
    pub fn which(&self) -> Option<LimitName> {
        match self {
            UiLimitError::UiTreeTooLarge { which, .. } => Some(*which),
        }
    }
}

impl fmt::Display for UiLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UiLimitError::UiTreeTooLarge {
                which,
                limit,
                observed,
            } => write!(
                f,
                "{}: ui tree exceeds {} (limit {}, observed {})",
                self.code(),
                which.as_str(),
                limit,
                observed
            ),
        }
    }
}

impl std::error::Error for UiLimitError {}

/// Host-configurable limits on a capsule's UI tree. Every limit is inclusive:
/// a tree whose value equals the limit is accepted, and only a strictly larger
/// value is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiLimits {
    /// The maximum number of nodes. Zero refuses any non-empty tree.
    pub max_nodes: u64,
    /// The maximum depth, the root being depth 1. Zero refuses any non-empty
    /// tree.
    pub max_depth: u64,
    /// The maximum total bytes of all node text.
    pub max_text_bytes: u64,
}

impl UiLimits {
    /// Build limits from host config. No default is applied and no limit is
    /// adjusted; a zero stays zero.
    pub fn new(max_nodes: u64, max_depth: u64, max_text_bytes: u64) -> Self {
        UiLimits {
            max_nodes,
            max_depth,
            max_text_bytes,
        }
    }

    /// The small conservative preset used by tests and by any caller that has
    /// no host config yet: 64 nodes, depth 8, 4096 text bytes.
    pub fn small_preset() -> Self {
        UiLimits::new(64, 8, 4096)
    }

    /// Check a UI tree against every limit. The first exceeded limit in the
    /// order nodes, depth, text bytes is reported as
    /// [`UiLimitError::UiTreeTooLarge`], naming that limit.
    ///
    /// All three limits are evaluated against the whole tree before deciding,
    /// so the refusal names the limit the tree actually breaks rather than
    /// whichever node happened to be visited first.
    pub fn check(&self, tree: &UiTree) -> Result<(), UiLimitError> {
        if tree.node_count > self.max_nodes {
            return Err(UiLimitError::UiTreeTooLarge {
                which: LimitName::MaxNodes,
                limit: self.max_nodes,
                observed: tree.node_count,
            });
        }
        if tree.depth > self.max_depth {
            return Err(UiLimitError::UiTreeTooLarge {
                which: LimitName::MaxDepth,
                limit: self.max_depth,
                observed: tree.depth,
            });
        }
        if tree.text_bytes > self.max_text_bytes {
            return Err(UiLimitError::UiTreeTooLarge {
                which: LimitName::MaxTextBytes,
                limit: self.max_text_bytes,
                observed: tree.text_bytes,
            });
        }
        Ok(())
    }
}

/// One node of a capsule's UI tree, as measured against [`UiLimits`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiNode {
    /// The node's text, if it has any. Its `len()` counts toward
    /// `max_text_bytes`.
    pub text: Option<String>,
    /// The node's children. Their subtrees are part of the same tree.
    pub children: Vec<UiNode>,
}

impl UiNode {
    /// A node with no text and no children.
    pub fn new() -> Self {
        UiNode {
            text: None,
            children: Vec::new(),
        }
    }

    /// A node with the given text and no children.
    pub fn with_text(text: impl Into<String>) -> Self {
        UiNode {
            text: Some(text.into()),
            children: Vec::new(),
        }
    }

    /// Return this node with the given children.
    pub fn with_children(mut self, children: Vec<UiNode>) -> Self {
        self.children = children;
        self
    }
}

impl Default for UiNode {
    fn default() -> Self {
        UiNode::new()
    }
}

/// A capsule's UI tree measured against the limits: the numbers
/// [`UiLimits::check`] compares, computed once from the nodes. The root is
/// depth 1, an empty tree has zero nodes and depth 0, and `text_bytes` is the
/// sum of every node's text bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiTree {
    /// Number of nodes in the tree.
    pub node_count: u64,
    /// Depth of the deepest node, the root being depth 1. Zero for an empty
    /// tree.
    pub depth: u64,
    /// Total bytes of all node text.
    pub text_bytes: u64,
}

impl UiTree {
    /// An empty tree: no nodes, no depth, no text.
    pub fn empty() -> Self {
        UiTree {
            node_count: 0,
            depth: 0,
            text_bytes: 0,
        }
    }

    /// Measure a root node and its subtrees. The root is depth 1.
    pub fn measure(root: &UiNode) -> Self {
        let mut tree = UiTree::empty();
        UiTree::walk(root, 1, &mut tree);
        tree
    }

    fn walk(node: &UiNode, depth: u64, tree: &mut UiTree) {
        tree.node_count += 1;
        if depth > tree.depth {
            tree.depth = depth;
        }
        if let Some(text) = &node.text {
            tree.text_bytes += text.len() as u64;
        }
        for child in &node.children {
            UiTree::walk(child, depth + 1, tree);
        }
    }
}

impl Default for UiTree {
    fn default() -> Self {
        UiTree::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(text: &str) -> UiNode {
        UiNode::with_text(text)
    }

    // P6: a tree within every limit is accepted. The limits bound the tree
    // and do not reject reasonable trees.
    #[test]
    fn tree_within_limits_is_accepted() {
        let limits = UiLimits::small_preset();
        let tree = UiTree::measure(
            &UiNode::new().with_children(vec![leaf("hello"), leaf("world")]),
        );
        assert_eq!(tree.node_count, 3);
        assert_eq!(tree.depth, 2);
        assert_eq!(tree.text_bytes, 10);
        assert_eq!(limits.check(&tree), Ok(()));
    }

    // P6: a tree exactly at every limit is accepted; the limits are inclusive.
    #[test]
    fn tree_at_every_limit_is_accepted() {
        let limits = UiLimits::new(1, 1, 5);
        let tree = UiTree::measure(&leaf("12345"));
        assert_eq!(tree.node_count, 1);
        assert_eq!(tree.depth, 1);
        assert_eq!(tree.text_bytes, 5);
        assert_eq!(limits.check(&tree), Ok(()));
    }

    // P6: exceeding the node count is refused, and the refusal names
    // `max_nodes` rather than another limit.
    #[test]
    fn node_limit_refuses_and_names_max_nodes() {
        let limits = UiLimits::new(2, 8, 4096);
        let tree = UiTree::measure(&UiNode::new().with_children(vec![leaf("a"), leaf("b")]));
        let err = limits.check(&tree).expect_err("three nodes exceed a limit of two");
        assert_eq!(err.code(), "ui_tree_too_large");
        assert_eq!(err.which(), Some(LimitName::MaxNodes));
    }

    // P6: exceeding the depth is refused, and the refusal names `max_depth`.
    // Here the node count is within its limit and only depth is exceeded.
    #[test]
    fn depth_limit_refuses_and_names_max_depth() {
        let limits = UiLimits::new(8, 2, 4096);
        let tree = UiTree::measure(&UiNode::new().with_children(vec![UiNode::new()
            .with_children(vec![leaf("deep")])]));
        assert_eq!(tree.node_count, 3);
        assert_eq!(tree.depth, 3);
        let err = limits.check(&tree).expect_err("depth three exceeds a limit of two");
        assert_eq!(err.code(), "ui_tree_too_large");
        assert_eq!(err.which(), Some(LimitName::MaxDepth));
    }

    // P6: exceeding the total text bytes is refused, and the refusal names
    // `max_text_bytes`. The count and depth are within their limits.
    #[test]
    fn text_bytes_limit_refuses_and_names_max_text_bytes() {
        let limits = UiLimits::new(8, 8, 5);
        let tree = UiTree::measure(&UiNode::new().with_children(vec![leaf("abc"), leaf("defg")]));
        assert_eq!(tree.node_count, 3);
        assert_eq!(tree.depth, 2);
        assert_eq!(tree.text_bytes, 7);
        let err = limits.check(&tree).expect_err("seven text bytes exceed a limit of five");
        assert_eq!(err.code(), "ui_tree_too_large");
        assert_eq!(err.which(), Some(LimitName::MaxTextBytes));
    }

    // P10: every limit at zero, on a non-empty tree, refuses it and names the
    // zeroed limit. Each zero limit on its own refuses a tree that is within
    // the other two limits.
    #[test]
    fn zero_limits_refuse_any_tree() {
        let tree = UiTree::measure(&leaf("x"));
        assert_eq!(tree.node_count, 1);
        assert_eq!(tree.depth, 1);
        assert_eq!(tree.text_bytes, 1);

        let all_zero = UiLimits::new(0, 0, 0);
        let err = all_zero.check(&tree).expect_err("zero node limit refuses a one-node tree");
        assert_eq!(err.code(), "ui_tree_too_large");
        assert_eq!(err.which(), Some(LimitName::MaxNodes));

        let ok_counts = UiLimits::new(8, 8, 8);
        assert_eq!(ok_counts.check(&tree), Ok(()));

        let zero_nodes = UiLimits::new(0, 8, 8);
        assert_eq!(
            zero_nodes.check(&tree).unwrap_err().which(),
            Some(LimitName::MaxNodes)
        );

        let zero_depth = UiLimits::new(8, 0, 8);
        assert_eq!(
            zero_depth.check(&tree).unwrap_err().which(),
            Some(LimitName::MaxDepth)
        );

        let zero_text = UiLimits::new(8, 8, 0);
        assert_eq!(
            zero_text.check(&tree).unwrap_err().which(),
            Some(LimitName::MaxTextBytes)
        );
    }

    // P10: the empty tree measures zero nodes, depth 0 and no text, so it fits
    // zero node and zero depth limits because the limits are inclusive; all
    // zero limits therefore do not refuse it. The rule that "zero limits refuse
    // any tree" applies to every non-empty tree, which needs at least one node
    // at depth 1 and is refused by a zero node or zero depth limit.
    #[test]
    fn zero_limits_refuse_the_empty_tree() {
        let empty = UiTree::empty();
        assert_eq!(empty.node_count, 0);
        assert_eq!(empty.depth, 0);
        assert_eq!(empty.text_bytes, 0);

        // Inclusive limits: an empty tree at or under zero node and depth
        // limits is accepted.
        let all_zero = UiLimits::new(0, 0, 0);
        assert_eq!(all_zero.check(&empty), Ok(()));

        // Any non-empty tree at the same all-zero limits is refused, naming the
        // zeroed node limit first.
        let one = UiTree::measure(&UiNode::new());
        let err = all_zero
            .check(&one)
            .expect_err("zero limits refuse every non-empty tree");
        assert_eq!(err.code(), "ui_tree_too_large");
        assert_eq!(err.which(), Some(LimitName::MaxNodes));
    }

    // P10: the Display text is `<code>: <explanation>` and uses the relative
    // limit name, with no host path.
    #[test]
    fn display_is_code_then_explanation() {
        let err = UiLimits::new(1, 1, 1)
            .check(&UiTree::measure(&UiNode::new().with_children(vec![leaf("ab")])))
            .unwrap_err();
        let shown = err.to_string();
        assert!(shown.starts_with("ui_tree_too_large: "), "shown was {shown}");
        assert!(shown.contains("max_nodes"), "shown was {shown}");
        assert!(!shown.contains('/'), "shown was {shown}");
    }
}
