//! The Runtime capabilities the journeys need, which check needs which, and
//! the source evidence that each capability is still missing.
//!
//! A pin is evidence of a gap, never of a capability. When a pin stops
//! holding, the gap is stale: re-measure that capability against a live
//! operator, then update this table and SPEC.md together.

use std::path::Path;

use crate::contract::{Fixture, ResidentRuntime};
use crate::journey;
use crate::wit::Wit;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    ResidentWorld,
    LiveLaunch,
    InstanceList,
    InstanceStop,
    Settlement,
    PendingOutlivesCall,
    LiveGrantView,
}

pub enum Rule {
    /// The file holds this text, compared with whitespace runs collapsed.
    Contains(&'static str),
    Lacks(&'static str),
    /// Between the `start` and `end` anchors the file lacks `needle`.
    LacksBetween {
        start: &'static str,
        end: &'static str,
        needle: &'static str,
    },
    /// No world in the WIT directory exports an interface that defines both
    /// `start` and `stop`.
    NoResidentExport,
    /// Every WIT interface named `capabilities` defines only `request`, and it
    /// returns the grant itself.
    BlockingCapabilityRequest,
}

pub struct Pin {
    /// Relative to the repository root.
    pub path: &'static str,
    pub rule: Rule,
    pub meaning: &'static str,
}

const WIT: &str = "elastos/wit";
const COMPONENT: &str = "elastos/crates/elastos-compute/src/providers/component.rs";
const ROUTES: &str = "elastos/crates/elastos-server/src/api/routes.rs";
const SERVER: &str = "elastos/crates/elastos-server/src/api/server.rs";
const RUNTIME: &str = "elastos/crates/elastos-server/src/runtime.rs";
const CAPABILITY: &str = "elastos/crates/elastos-server/src/api/handlers/capability.rs";
const BRIDGE: &str = "elastos/crates/elastos-server/src/resource_bridge.rs";

const RESIDENT_WORLD: &[Pin] = &[
    Pin {
        path: WIT,
        rule: Rule::NoResidentExport,
        meaning: "no Bus world exports a resident lifecycle; world product-capsule-v1 exports lifecycle.run only",
    },
    Pin {
        path: COMPONENT,
        rule: Rule::Contains("world: \"product-capsule-v1\","),
        meaning: "the component provider binds only the run-once world",
    },
];

const LIVE_LAUNCH: &[Pin] = &[
    Pin {
        path: ROUTES,
        rule: Rule::Contains(
            "let status = if handle.manifest.is_component_capsule() { \"completed\" } else { \"launched\" };",
        ),
        meaning: "POST /api/capsules answers a component launch after lifecycle.run returned, with status completed",
    },
    Pin {
        path: ROUTES,
        rule: Rule::Lacks("session_id"),
        meaning: "the launch response names no Bus session",
    },
];

const INSTANCE_LIST: &[Pin] = &[Pin {
    path: RUNTIME,
    rule: Rule::LacksBetween {
        start: "pub async fn run_local_with_principal(",
        end: "async fn check_provider_dependencies(",
        needle: "register_capsule",
    },
    meaning: "a component activation is never registered, so GET /api/capsules cannot list it",
}];

const INSTANCE_STOP: &[Pin] = &[Pin {
    path: COMPONENT,
    rule: Rule::Contains(
        "component/v1 is a bounded activation contract and has no resident stop operation",
    ),
    meaning: "the component provider refuses to stop a running component",
}];

const SETTLEMENT: &[Pin] = &[
    Pin {
        path: SERVER,
        rule: Rule::Lacks("/api/capability/requests"),
        meaning: "no shell route reads a session's settled requests",
    },
    Pin {
        path: CAPABILITY,
        rule: Rule::Contains("Cannot access another session's request"),
        meaning: "a request's status is readable only by the session that asked",
    },
    Pin {
        path: BRIDGE,
        rule: Rule::Contains("\"message\": \"capability request not approved within 30s\","),
        meaning: "a component's wait ends in a timeout that leaves its request pending; nothing settles it when the instance ends",
    },
];

const PENDING_OUTLIVES_CALL: &[Pin] = &[
    Pin {
        path: WIT,
        rule: Rule::BlockingCapabilityRequest,
        meaning: "the only capability call returns the grant, so the guest waits inside it",
    },
    Pin {
        path: BRIDGE,
        rule: Rule::Contains("// Poll for the shell's decision (AutoGrantEngine or manual)."),
        meaning: "the in-process bridge polls for the decision inside the guest's call",
    },
];

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
];

impl Capability {
    pub const ALL: [Capability; 7] = [
        Capability::ResidentWorld,
        Capability::LiveLaunch,
        Capability::InstanceList,
        Capability::InstanceStop,
        Capability::Settlement,
        Capability::PendingOutlivesCall,
        Capability::LiveGrantView,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Capability::ResidentWorld => "RI-1",
            Capability::LiveLaunch => "RI-2",
            Capability::InstanceList => "RI-3",
            Capability::InstanceStop => "RI-4",
            Capability::Settlement => "RI-5",
            Capability::PendingOutlivesCall => "RI-6",
            Capability::LiveGrantView => "RI-7",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Capability::ResidentWorld => "resident component world in the Bus WIT",
            Capability::LiveLaunch => "launch returns a live instance with its Bus session",
            Capability::InstanceList => "shell list of live instances with status and cause",
            Capability::InstanceStop => "stop one instance with a reason",
            Capability::Settlement => {
                "Runtime settles an ended instance's requests, shell reads the record"
            }
            Capability::PendingOutlivesCall => {
                "a capability request can stay pending after the guest's call returns"
            }
            Capability::LiveGrantView => "shell view of every session's live grants",
        }
    }

    /// `Some` while the capability is missing, with the evidence for the gap.
    /// A capability leaves this list only after a live journey measured it.
    pub fn gap(self) -> Option<&'static [Pin]> {
        Some(match self {
            Capability::ResidentWorld => RESIDENT_WORLD,
            Capability::LiveLaunch => LIVE_LAUNCH,
            Capability::InstanceList => INSTANCE_LIST,
            Capability::InstanceStop => INSTANCE_STOP,
            Capability::Settlement => SETTLEMENT,
            Capability::PendingOutlivesCall => PENDING_OUTLIVES_CALL,
            Capability::LiveGrantView => LIVE_GRANT_VIEW,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    A3,
    A6,
    A10,
    A11,
    A12,
}

impl Check {
    pub const ALL: [Check; 5] = [Check::A3, Check::A6, Check::A10, Check::A11, Check::A12];

    pub fn id(self) -> &'static str {
        match self {
            Check::A3 => "A3",
            Check::A6 => "A6",
            Check::A10 => "A10",
            Check::A11 => "A11",
            Check::A12 => "A12",
        }
    }

    pub fn test_name(self) -> &'static str {
        match self {
            Check::A3 => "acceptance_a3_two_resident_instances_in_one_runtime",
            Check::A6 => "acceptance_a6_instance_grant_does_not_authorise_sibling",
            Check::A10 => "acceptance_a10_cancel_one_instance_sibling_unaffected",
            Check::A11 => "acceptance_a11_failed_instance_request_settled_by_runtime",
            Check::A12 => "acceptance_a12_stopped_instances_leave_nothing_behind",
        }
    }

    pub fn needs(self) -> &'static [Capability] {
        use Capability::*;
        match self {
            Check::A3 => &[ResidentWorld, LiveLaunch, InstanceList, InstanceStop],
            Check::A6 => &[
                ResidentWorld,
                LiveLaunch,
                InstanceList,
                InstanceStop,
                LiveGrantView,
            ],
            Check::A10 => &[
                ResidentWorld,
                LiveLaunch,
                InstanceList,
                InstanceStop,
                Settlement,
            ],
            Check::A11 => &[
                ResidentWorld,
                LiveLaunch,
                InstanceList,
                InstanceStop,
                Settlement,
                PendingOutlivesCall,
            ],
            Check::A12 => &[
                ResidentWorld,
                LiveLaunch,
                InstanceList,
                InstanceStop,
                LiveGrantView,
            ],
        }
    }

    pub fn fixtures(self) -> &'static [Fixture] {
        match self {
            Check::A11 => &[Fixture::FailAfterSubmit, Fixture::ReadShared],
            _ => &[Fixture::ReadShared],
        }
    }

    pub fn blocked(self) -> Vec<Capability> {
        self.needs()
            .iter()
            .copied()
            .filter(|capability| capability.gap().is_some())
            .collect()
    }

    pub fn run<R: ResidentRuntime>(self, runtime: &mut R) -> journey::Outcome {
        match self {
            Check::A3 => journey::a3_two_resident_instances(runtime),
            Check::A6 => journey::a6_separate_grants(runtime),
            Check::A10 => journey::a10_cancel_one_instance(runtime),
            Check::A11 => journey::a11_failed_instance_settled(runtime),
            Check::A12 => journey::a12_cleanup_census(runtime),
        }
    }
}

/// `RI-1; RI-2`, the form the ignored acceptance rows carry.
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
        Rule::LacksBetween { start, end, needle } => {
            let text = text()?;
            let from = text
                .find(start)
                .ok_or(format!("{}: anchor {start:?} is gone", pin.path))?;
            let to = text[from..]
                .find(end)
                .ok_or(format!("{}: anchor {end:?} is gone", pin.path))?;
            Ok(Reading {
                holds: !text[from..from + to].contains(needle),
                line: Some(text[..from].matches('\n').count() + 1),
            })
        }
        Rule::NoResidentExport => Ok(Reading {
            holds: Wit::read_dir(&path)?
                .exports_defining(&["start", "stop"])
                .is_empty(),
            line: None,
        }),
        Rule::BlockingCapabilityRequest => {
            let wit = Wit::read_dir(&path)?;
            let mut seen = false;
            let mut holds = true;
            for funcs in wit.interfaces_named("capabilities") {
                seen = true;
                holds &= funcs.len() == 1
                    && funcs[0].name == "request"
                    && funcs[0]
                        .signature
                        .contains("-> result<capability-grant, bus-error>");
            }
            Ok(Reading {
                holds: seen && holds,
                line: None,
            })
        }
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
        let text = "a\nlet status = if x {\n    \"completed\"\n} else {\n    \"launched\"\n};\n";
        assert_eq!(
            find(
                text,
                "let status = if x { \"completed\" } else { \"launched\" };"
            ),
            Some(2)
        );
        assert_eq!(find(text, "if x { \"launched\""), None);
        assert_eq!(find("one\ntwo three", "two   three"), Some(2));
    }

    #[test]
    fn every_check_needs_the_resident_core_and_lists_it_first() {
        for check in Check::ALL {
            assert_eq!(
                &check.needs()[..4],
                &[
                    Capability::ResidentWorld,
                    Capability::LiveLaunch,
                    Capability::InstanceList,
                    Capability::InstanceStop
                ],
                "{}",
                check.id()
            );
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
}
