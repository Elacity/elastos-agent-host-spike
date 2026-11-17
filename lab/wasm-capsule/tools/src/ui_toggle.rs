//! `ui_toggle`: a host-side toggle (switch) node for the wasm-capsule lab.
//!
//! This module is self-contained plain data plus its rules: it runs no
//! capsule code and talks to no Runtime. Following P6, a UI action resolves
//! to a Runtime capability request: [`ToggleNode::toggle`] and
//! [`ToggleNode::set`] are the local intent, and the [`ToggleEvent`] they
//! return carries only the new on/off value for the host to forward. The host
//! renders the label; the capsule never renders it.
//!
//! Preset chosen here (small and conservative): a label may not be empty and
//! may hold at most [`LABEL_MAX_CHARS`] characters (80). A change attempted on
//! a disabled toggle is [`ToggleError::NodeDisabled`], whose stable code is
//! `node_disabled`.

use std::fmt;

/// The maximum number of characters a toggle label may hold.
pub const LABEL_MAX_CHARS: usize = 80;

/// A toggle node: a host-rendered label and an on/off value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToggleNode {
    label: String,
    on: bool,
    enabled: bool,
}

/// The event a toggle emits: the new on/off value only, never the label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToggleEvent {
    new_value: bool,
}

impl ToggleEvent {
    /// The new on/off value carried by this event.
    pub fn new_value(&self) -> bool {
        self.new_value
    }
}

/// A refusal raised by a toggle operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToggleError {
    /// The label was empty or longer than [`LABEL_MAX_CHARS`] characters.
    InvalidLabel,
    /// A change was attempted on a disabled toggle.
    NodeDisabled,
}

impl ToggleError {
    /// The stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            ToggleError::InvalidLabel => "invalid_label",
            ToggleError::NodeDisabled => "node_disabled",
        }
    }
}

impl fmt::Display for ToggleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            ToggleError::InvalidLabel => "the label must be non-empty and at most 80 characters",
            ToggleError::NodeDisabled => "the toggle is disabled and refuses changes",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for ToggleError {}

impl ToggleNode {
    /// Build a new enabled toggle, off by default.
    pub fn new(label: &str) -> Result<ToggleNode, ToggleError> {
        validate_label(label)?;
        Ok(ToggleNode {
            label: label.to_string(),
            on: false,
            enabled: true,
        })
    }

    /// Build a new toggle with the given initial value and enabled state.
    pub fn with_state(label: &str, on: bool, enabled: bool) -> Result<ToggleNode, ToggleError> {
        validate_label(label)?;
        Ok(ToggleNode {
            label: label.to_string(),
            on,
            enabled,
        })
    }

    /// The label the host renders. The capsule never renders this.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The current on/off value.
    pub fn value(&self) -> bool {
        self.on
    }

    /// Whether this toggle currently accepts changes.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Flip the value and emit an event carrying the new value only.
    pub fn toggle(&mut self) -> Result<ToggleEvent, ToggleError> {
        self.set(!self.on)
    }

    /// Set the value and emit an event carrying the new value only.
    pub fn set(&mut self, after: bool) -> Result<ToggleEvent, ToggleError> {
        if !self.enabled {
            return Err(ToggleError::NodeDisabled);
        }
        self.on = after;
        Ok(ToggleEvent { new_value: after })
    }
}

fn validate_label(label: &str) -> Result<(), ToggleError> {
    if label.is_empty() || label.chars().count() > LABEL_MAX_CHARS {
        return Err(ToggleError::InvalidLabel);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // P6: the host renders the label the node stores, not the capsule.
    #[test]
    fn host_renders_stored_label() {
        let node = ToggleNode::new("Dark mode").expect("valid label");
        assert_eq!(node.label(), "Dark mode");
    }

    // P6: a toggle event carries only the new value, and the value flips.
    #[test]
    fn toggle_event_carries_only_new_value() {
        let mut node = ToggleNode::new("Wi-Fi").expect("valid label");
        assert!(!node.value());
        let event = node.toggle().expect("enabled toggle accepts change");
        assert!(event.new_value());
        assert!(node.value());
        let event = node.toggle().expect("enabled toggle accepts change");
        assert!(!event.new_value());
        assert!(!node.value());
    }

    // P6: a disabled toggle refuses changes with the node_disabled code and
    // leaves the value unchanged.
    #[test]
    fn disabled_toggle_refuses_changes() {
        let mut node = ToggleNode::with_state("Airplane", false, false).expect("valid label");
        let refusal = node.toggle().expect_err("disabled toggle refuses");
        assert_eq!(refusal.code(), "node_disabled");
        let refusal = node.set(true).expect_err("disabled toggle refuses");
        assert_eq!(refusal.code(), "node_disabled");
        assert!(!node.value(), "a refused change leaves the value unchanged");
    }

    // P6: an enabled toggle accepts arbitrary text, including colons.
    #[test]
    fn enabled_toggle_accepts_colon_text() {
        let mut node =
            ToggleNode::with_state("line one: line two", false, true).expect("valid label");
        let event = node.toggle().expect("enabled toggle accepts change");
        assert!(event.new_value());
    }

    // P6: the label cap is exactly 80 characters; 81 is refused.
    #[test]
    fn label_length_is_capped() {
        let at_cap = "a".repeat(LABEL_MAX_CHARS);
        ToggleNode::new(&at_cap).expect("80 characters is allowed");
        let over_cap = "a".repeat(LABEL_MAX_CHARS + 1);
        let refusal = ToggleNode::new(&over_cap).expect_err("81 characters is refused");
        assert_eq!(refusal.code(), "invalid_label");
    }

    // P6: an empty label is refused with a stable code.
    #[test]
    fn empty_label_is_refused() {
        let refusal = ToggleNode::new("").expect_err("empty label is refused");
        assert_eq!(refusal.code(), "invalid_label");
    }

    // P6: a toggle that starts on reports its initial value and can be set.
    #[test]
    fn initial_value_and_set_are_consistent() {
        let mut node = ToggleNode::with_state("Mute", true, true).expect("valid label");
        assert!(node.value());
        let event = node.set(false).expect("enabled toggle accepts change");
        assert!(!event.new_value());
        assert!(!node.value());
    }
}
