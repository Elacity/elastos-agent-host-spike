//! Acceptance harness for M1 check A5: grants bound to agent identity,
//! session, capsule instance and owned storage.
//!
//! The journeys in [`journey`] state each row once, against the
//! [`contract::BindingRuntime`] interface that `SPEC.md` asks the Runtime to
//! expose. [`acceptance`] grades a row against a live operator only; until
//! every capability the row needs exists, it reports BLOCKED with the exact
//! missing RA-* ask and the source evidence for the gap. `PASS` is built only
//! from live operator evidence that is not a Public-storage read.

pub mod capability;
pub mod contract;
pub mod http;
pub mod journey;

use std::path::PathBuf;

use capability::Check;
use contract::grade_pass;

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

/// True only for a live-operator PASS. SKIPPED, BLOCKED and FAIL are never
/// accepted. A falsifier that also matches SKIPPED is caught by
/// `skipped_is_never_accepted`.
pub fn counts_as_accepted(grade: &Grade) -> bool {
    matches!(grade, Grade::Pass(_))
}

/// The checkout this lane sits in. Evidence pins are read from it.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Grade one row. A missing capability blocks before any setup is read, so
/// a blocked row never touches an operator.
pub fn acceptance(check: Check) -> Grade {
    let blocked = check.blocked();
    if !blocked.is_empty() {
        return Grade::Blocked(capability::describe(&blocked, &repo_root()));
    }
    let setup = match http::Setup::from_env() {
        Ok(setup) => setup,
        Err(reason) => return Grade::Skipped(reason),
    };
    let mut runtime = match http::OperatorRuntime::attach(&setup) {
        Ok(runtime) => runtime,
        Err(reason) => return Grade::Skipped(format!("operator attach failed: {reason}")),
    };
    match check.run(&mut runtime) {
        Ok(_text) => match runtime.take_binding_evidence() {
            Some(evidence) => match grade_pass(evidence) {
                Ok(grade) => grade,
                Err(reason) => Grade::Fail(reason),
            },
            None => Grade::Fail(
                "journey returned ok without live operator evidence; PASS requires a Runtime response"
                    .to_owned(),
            ),
        },
        Err(reason) => Grade::Fail(reason),
    }
}
