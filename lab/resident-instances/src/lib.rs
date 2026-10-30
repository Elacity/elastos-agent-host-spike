//! Acceptance harness for resident capsule instances inside one Runtime.
//!
//! The journeys in [`journey`] state M1 checks A3, A6, A10, A11 and A12 once,
//! against the [`contract::ResidentRuntime`] interface that `SPEC.md` asks the
//! Runtime to expose. [`acceptance`] grades a check against a live operator
//! only; until every capability the check needs exists, it reports BLOCKED
//! with the exact missing capability and the source evidence for the gap.

pub mod capability;
pub mod contract;
pub mod http;
pub mod journey;
pub mod wit;

use std::path::PathBuf;

use capability::Check;

/// One acceptance row. `Pass` is built only from a journey that ran against a
/// live operator; nothing else in this crate constructs it.
#[derive(Debug, PartialEq, Eq)]
pub enum Grade {
    Pass(String),
    Fail(String),
    Blocked(String),
    Skipped(String),
}

impl Grade {
    pub fn label(&self) -> &'static str {
        match self {
            Grade::Pass(_) => "PASS",
            Grade::Fail(_) => "FAIL",
            Grade::Blocked(_) => "BLOCKED",
            Grade::Skipped(_) => "SKIPPED",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Grade::Pass(text) | Grade::Fail(text) | Grade::Blocked(text) | Grade::Skipped(text) => {
                text
            }
        }
    }
}

/// The checkout this lane sits in. Evidence pins are read from it.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Grade one check. A missing capability blocks before any setup is read, so
/// a blocked row never touches an operator.
pub fn acceptance(check: Check) -> Grade {
    let blocked = check.blocked();
    if !blocked.is_empty() {
        return Grade::Blocked(capability::describe(&blocked, &repo_root()));
    }
    let setup = match http::Setup::from_env(check) {
        Ok(setup) => setup,
        Err(reason) => return Grade::Skipped(reason),
    };
    let mut runtime = match http::OperatorRuntime::attach(&setup) {
        Ok(runtime) => runtime,
        Err(reason) => return Grade::Skipped(format!("operator attach failed: {reason}")),
    };
    match check.run(&mut runtime) {
        Ok(evidence) => Grade::Pass(evidence),
        Err(reason) => Grade::Fail(reason),
    }
}
