//! The RA-* capabilities the rows need, which row needs which, and the
//! source evidence that each capability is still missing.
//!
//! A pin is evidence of a gap, never of a capability. When a pin stops
//! holding, the gap is stale: re-measure that capability against a live
//! operator, then update this table and SPEC.md together.

use std::path::Path;

use crate::contract::BindingRuntime;
use crate::journey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    LiveGrantView,
    Settlement,
    HomeStorage,
    UsersAiAlias,
    ResidentCore,
}

pub enum Rule {
    /// The file holds this text, compared with whitespace runs collapsed.
    Contains(&'static str),
    Lacks(&'static str),
}

pub struct Pin {
    /// Relative to the repository root.
    pub path: &'static str,
    pub rule: Rule,
    pub meaning: &'static str,
}

const ROUTES: &str = "elastos/crates/elastos-server/src/api/routes.rs";
const SERVER: &str = "elastos/crates/elastos-server/src/api/server.rs";
const CAPABILITY: &str = "elastos/crates/elastos-server/src/api/handlers/capability.rs";
const COMPONENT: &str = "elastos/crates/elastos-compute/src/providers/component.rs";
const RUN_CMD: &str = "elastos/crates/elastos-server/src/run_cmd.rs";
const BRIDGE: &str = "elastos/crates/elastos-server/src/resource_bridge.rs";
const AUTH: &str = "elastos/crates/elastos-server/src/auth.rs";
const REGISTRY: &str = "elastos/crates/elastos-runtime/src/session/registry.rs";
const TOKEN: &str = "elastos/crates/elastos-runtime/src/capability/token.rs";

const LIVE_GRANT_VIEW: &[Pin] = &[
    Pin {
        path: CAPABILITY,
        rule: Rule::Lacks("all_sessions_live"),
        meaning: "no shell view of every session's live grants",
    },
    Pin {
        path: CAPABILITY,
        rule: Rule::Contains(
            "let granted_requests = state.pending_store.list_session_granted(&session_id).await;",
        ),
        meaning: "GET /api/capability/list returns the caller's own session grants",
    },
    Pin {
        path: TOKEN,
        rule: Rule::Contains("/// Who can use this token (capsule ID)"),
        meaning: "a capability token names a capsule id and holds no agent identity",
    },
];

const SETTLEMENT: &[Pin] = &[
    Pin {
        path: SERVER,
        rule: Rule::Lacks("/api/capability/requests"),
        meaning: "no shell route reads a session's settled requests",
    },
    Pin {
        path: REGISTRY,
        rule: Rule::Contains(r#"reason: "invalidated".to_string(),"#),
        meaning: "ending a session emits invalidated and revokes no grant",
    },
    Pin {
        path: CAPABILITY,
        rule: Rule::Contains("Cannot access another session's request"),
        meaning: "a request's status is readable only by the session that asked",
    },
];

const HOME_STORAGE: &[Pin] = &[Pin {
    path: RUN_CMD,
    rule: Rule::Contains(r#"crate::create_runtime("/tmp/elastos/storage")"#),
    meaning: "elastos run still builds storage at /tmp/elastos/storage",
}];

const USERS_AI_ALIAS: &[Pin] = &[
    Pin {
        path: BRIDGE,
        rule: Rule::Contains(
            r#"return Err(
            "localhost://Users roots must use Users/self or the active principal root".to_string(),
        );
    }

    Ok(rooted)"#,
        ),
        meaning: "scope_current_user_alias leaves UsersAI unchanged after the Users/self rule",
    },
    Pin {
        path: AUTH,
        rule: Rule::Contains(r#"format!("localhost://Users/{}", hex::encode(&digest[..12]))"#),
        meaning: "the only principal-to-root map is localhost://Users/<hash>",
    },
];

const RESIDENT_CORE: &[Pin] = &[
    Pin {
        path: COMPONENT,
        rule: Rule::Contains(r#"world: "product-capsule-v1","#),
        meaning: "the component provider binds only the run-once world",
    },
    Pin {
        path: COMPONENT,
        rule: Rule::Contains(
            "component/v1 is a bounded activation contract and has no resident stop operation",
        ),
        meaning: "the component provider refuses to stop a running component",
    },
    Pin {
        path: ROUTES,
        rule: Rule::Contains(r#""completed""#),
        meaning: "POST /api/capsules answers a component launch after lifecycle.run returned, with status completed",
    },
    Pin {
        path: ROUTES,
        rule: Rule::Lacks("session_id"),
        meaning: "the launch response names no Bus session",
    },
];

impl Capability {
    pub const ALL: [Capability; 5] = [
        Capability::LiveGrantView,
        Capability::Settlement,
        Capability::HomeStorage,
        Capability::UsersAiAlias,
        Capability::ResidentCore,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Capability::LiveGrantView => "RA-1",
            Capability::Settlement => "RA-2",
            Capability::HomeStorage => "RA-3",
            Capability::UsersAiAlias => "RA-5",
            Capability::ResidentCore => "RA-6",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Capability::LiveGrantView => "a shell view of every session's live grants",
            Capability::Settlement => {
                "the Runtime settles an ended requester's pending requests, and the shell reads who settled"
            }
            Capability::HomeStorage => {
                "the run launcher takes its storage directory from the selected Home"
            }
            Capability::UsersAiAlias => {
                "a UsersAI alias that resolves to the verified agent principal's root"
            }
            Capability::ResidentCore => {
                "resident component instances: world, launch, list, stop"
            }
        }
    }

    pub fn pins(self) -> &'static [Pin] {
        match self {
            Capability::LiveGrantView => LIVE_GRANT_VIEW,
            Capability::Settlement => SETTLEMENT,
            Capability::HomeStorage => HOME_STORAGE,
            Capability::UsersAiAlias => USERS_AI_ALIAS,
            Capability::ResidentCore => RESIDENT_CORE,
        }
    }

    /// A guest journey on a real operator has measured this ask. Editing
    /// [`Self::gap`] to return `None` is not a measurement. There is no env
    /// override and no file that can clear this.
    pub fn guest_measured(self) -> bool {
        GuestMeasurement::from_operator().is_some_and(|m| m.includes(self))
    }

    /// Gap status derived by reading the pins in this checkout. It is never a
    /// hardcoded `Some`/`None`. Pins that still hold are a gap. Pins that
    /// moved stay a gap until a guest journey measured the ask.
    pub fn gap(self) -> Option<&'static [Pin]> {
        let pins = self.pins();
        let repo = crate::repo_root();
        let holds = pins.iter().all(|pin| {
            read_pin(pin, &repo)
                .map(|reading| reading.holds)
                .unwrap_or(true)
        });
        if holds {
            Some(pins)
        } else if self.guest_measured() {
            None
        } else {
            Some(pins)
        }
    }
}

/// Record written only after a guest presented a handle on a live operator.
/// No such record exists. An environment variable is not a measurement.
#[derive(Debug)]
pub struct GuestMeasurement {
    asks: Vec<Capability>,
}

impl GuestMeasurement {
    pub fn from_operator() -> Option<Self> {
        let _ = std::env::var_os("A5_RUNTIME_COORDS");
        None
    }

    pub fn includes(&self, capability: Capability) -> bool {
        self.asks.contains(&capability)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    IdentityUse,
    IdentityReplay,
    SessionUse,
    SessionEnded,
    InstanceUse,
    InstanceSibling,
    StorageUse,
    StorageOtherRoot,
    PublicNotBinding,
}

impl Check {
    pub const ALL: [Check; 9] = [
        Check::IdentityUse,
        Check::IdentityReplay,
        Check::SessionUse,
        Check::SessionEnded,
        Check::InstanceUse,
        Check::InstanceSibling,
        Check::StorageUse,
        Check::StorageOtherRoot,
        Check::PublicNotBinding,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Check::IdentityUse => "A5-ID-POS",
            Check::IdentityReplay => "A5-ID-REPLAY",
            Check::SessionUse => "A5-SESS-POS",
            Check::SessionEnded => "A5-SESS-END",
            Check::InstanceUse => "A5-INST-POS",
            Check::InstanceSibling => "A5-INST-SIB",
            Check::StorageUse => "A5-STOR-POS",
            Check::StorageOtherRoot => "A5-STOR-OTHER",
            Check::PublicNotBinding => "A5-PUB",
        }
    }

    pub fn test_name(self) -> &'static str {
        match self {
            Check::IdentityUse => "acceptance_a5_identity_grant_used_by_bound_agent",
            Check::IdentityReplay => "acceptance_a5_identity_grant_replayed_by_other_agent",
            Check::SessionUse => "acceptance_a5_session_grant_used_in_bound_session",
            Check::SessionEnded => "acceptance_a5_session_grant_reused_after_session_end",
            Check::InstanceUse => "acceptance_a5_instance_grant_used_by_bound_instance",
            Check::InstanceSibling => "acceptance_a5_instance_grant_used_by_sibling",
            Check::StorageUse => "acceptance_a5_owned_storage_grant_used_on_bound_root",
            Check::StorageOtherRoot => "acceptance_a5_owned_storage_grant_pointed_at_other_root",
            Check::PublicNotBinding => "acceptance_a5_public_storage_read_is_not_binding",
        }
    }

    pub fn needs(self) -> &'static [Capability] {
        use Capability::*;
        match self {
            Check::IdentityUse => &[LiveGrantView, UsersAiAlias, ResidentCore],
            Check::IdentityReplay => &[LiveGrantView, UsersAiAlias, ResidentCore],
            Check::SessionUse => &[LiveGrantView, ResidentCore],
            Check::SessionEnded => &[LiveGrantView, Settlement, ResidentCore],
            Check::InstanceUse => &[LiveGrantView, ResidentCore],
            Check::InstanceSibling => &[LiveGrantView, ResidentCore],
            Check::StorageUse => &[LiveGrantView, HomeStorage, UsersAiAlias, ResidentCore],
            Check::StorageOtherRoot => &[LiveGrantView, HomeStorage, UsersAiAlias, ResidentCore],
            Check::PublicNotBinding => &[ResidentCore],
        }
    }

    /// A row stays blocked until a guest journey measured each ask. Clearing
    /// [`Capability::gap`] is not that measurement.
    pub fn blocked(self) -> Vec<Capability> {
        self.needs()
            .iter()
            .copied()
            .filter(|capability| !capability.guest_measured())
            .collect()
    }

    pub fn run<R: BindingRuntime>(self, runtime: &mut R) -> journey::Outcome {
        match self {
            Check::IdentityUse => journey::identity_use(runtime),
            Check::IdentityReplay => journey::identity_replay(runtime),
            Check::SessionUse => journey::session_use(runtime),
            Check::SessionEnded => journey::session_ended(runtime),
            Check::InstanceUse => journey::instance_use(runtime),
            Check::InstanceSibling => journey::instance_sibling(runtime),
            Check::StorageUse => journey::storage_use(runtime),
            Check::StorageOtherRoot => journey::storage_other_root(runtime),
            Check::PublicNotBinding => journey::public_not_binding(runtime),
        }
    }
}

/// `RA-1; RA-5`, the form the ignored acceptance rows carry.
pub fn ids(capabilities: &[Capability]) -> String {
    capabilities
        .iter()
        .map(|c| c.id())
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reading {
    pub holds: bool,
    /// Line of a `Contains` match.
    pub line: Option<usize>,
}

pub fn read_pin(pin: &Pin, repo: &Path) -> Result<Reading, String> {
    let path = repo.join(pin.path);
    let not_found = || Reading {
        holds: false,
        line: None,
    };
    let text =
        || std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", pin.path));
    match pin.rule {
        Rule::Contains(needle) => {
            Ok(
                find(&text()?, needle).map_or_else(not_found, |line| Reading {
                    holds: true,
                    line: Some(line),
                }),
            )
        }
        Rule::Lacks(needle) => Ok(Reading {
            holds: find(&text()?, needle).is_none(),
            line: None,
        }),
    }
}

/// Line of the first match, comparing with whitespace runs collapsed.
fn find(text: &str, needle: &str) -> Option<usize> {
    let (flat, origin) = flatten(text);
    let (needle, _) = flatten(needle);
    let at = flat.find(needle.trim())?;
    Some(text[..origin[at]].matches('\n').count() + 1)
}

fn flatten(text: &str) -> (String, Vec<usize>) {
    let mut flat = String::with_capacity(text.len());
    let mut origin = Vec::with_capacity(text.len());
    let mut space = false;
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() {
            space = true;
            continue;
        }
        if space && !flat.is_empty() {
            flat.push(' ');
            origin.push(index);
        }
        space = false;
        for _ in 0..ch.len_utf8() {
            origin.push(index);
        }
        flat.push(ch);
    }
    (flat, origin)
}

/// The text of a BLOCKED row: each missing capability with its evidence as
/// read from this checkout now.
pub fn describe(blocked: &[Capability], repo: &Path) -> String {
    let mut lines = vec![format!("missing Runtime capabilities {}", ids(blocked))];
    for capability in blocked {
        lines.push(format!("{} {}", capability.id(), capability.title()));
        for pin in capability.gap().unwrap_or_default() {
            let place = match read_pin(pin, repo) {
                Ok(Reading { holds: true, line }) => format!(
                    "{}{} [holds]",
                    pin.path,
                    line.map(|l| format!(":{l}")).unwrap_or_default()
                ),
                Ok(Reading { holds: false, .. }) => format!(
                    "{} [MOVED: re-measure {} against a live operator]",
                    pin.path,
                    capability.id()
                ),
                Err(reason) => format!("{} [UNREADABLE: {reason}]", pin.path),
            };
            lines.push(format!("  evidence {place}: {}", pin.meaning));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_runs_do_not_change_a_match_or_its_line() {
        assert_eq!(find("one\ntwo three", "two   three"), Some(2));
        assert_eq!(find("one\ntwo three", "two four"), None);
    }

    #[test]
    fn every_row_needs_are_ordered_and_unique() {
        for check in Check::ALL {
            let mut sorted = check.needs().to_vec();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted,
                check.needs(),
                "{} needs are ordered and unique",
                check.id()
            );
        }
    }

    #[test]
    fn gap_cleared_without_guest_keeps_rows_blocked() {
        assert!(
            GuestMeasurement::from_operator().is_none(),
            "a guest measurement existed without a guest journey"
        );
        let repo = crate::repo_root();
        for capability in Capability::ALL {
            assert!(
                !capability.guest_measured(),
                "{} has no guest measurement",
                capability.id()
            );
            let gap = capability.gap();
            assert!(
                gap.is_some(),
                "gap() returned None without a guest measurement of {}",
                capability.id()
            );
            for pin in gap.unwrap() {
                let reading = read_pin(pin, &repo).expect("pin must be readable");
                assert!(
                    reading.holds,
                    "{} pin {} no longer holds; re-measure against a live operator",
                    capability.id(),
                    pin.path
                );
            }
        }
        for check in Check::ALL {
            assert_eq!(
                check.blocked(),
                check.needs(),
                "{} must stay blocked until a guest measures its asks",
                check.id()
            );
        }
    }

    #[test]
    fn gap_is_derived_from_pin_reads() {
        for capability in Capability::ALL {
            let gap = capability
                .gap()
                .unwrap_or_else(|| panic!("{} gap must come from pin reads", capability.id()));
            assert_eq!(gap.len(), capability.pins().len());
            assert!(std::ptr::eq(gap, capability.pins()));
        }
    }
}
