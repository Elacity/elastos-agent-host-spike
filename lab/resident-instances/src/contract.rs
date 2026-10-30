//! The Runtime interface the journeys need, as SPEC.md states it.

use std::time::Duration;

/// The one resource both fixture instances read. It sits inside the fixture
/// manifest's bound, so the Runtime's grant decides each read.
pub const SHARED_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";
pub const MANIFEST_BOUND: &str = "localhost://Public/resident-instances/*";
/// The guest compares the provider's answer with these bytes; the harness
/// seeds them through the Runtime's existing localhost write route.
pub const SHARED_BYTES: &[u8] = b"resident-instances shared fixture bytes\n";
pub const READ_REASON: &str = "resident instances: shared read";
pub const DENY_REASON: &str = "harness denies the sibling read";
pub const CANCEL_REASON: &str = "harness cancel: instance-1 cancelled mid-run";
pub const CLEANUP_REASON: &str = "harness cleanup: journey finished";

/// The two fixture guests. SPEC.md gives their exact behaviour; both are built
/// from one source against the resident Bus world (RI-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    /// `start` requests `read` on [`SHARED_RESOURCE`] and waits for the
    /// decision. Granted: read, compare with [`SHARED_BYTES`], return Ok and
    /// stay resident. Denied: return the denial as the start error.
    ReadShared,
    /// `start` submits the same request without waiting (RI-6), then traps.
    FailAfterSubmit,
}

impl Fixture {
    pub fn name(self) -> &'static str {
        match self {
            Fixture::ReadShared => "read-shared",
            Fixture::FailAfterSubmit => "fail-after-submit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Other(String),
}

impl State {
    pub fn parse(text: &str) -> State {
        match text {
            "starting" => State::Starting,
            "running" => State::Running,
            "stopping" => State::Stopping,
            "stopped" => State::Stopped,
            "failed" => State::Failed,
            other => State::Other(other.to_owned()),
        }
    }

    /// Live means the instance still holds Runtime resources.
    pub fn live(&self) -> bool {
        matches!(self, State::Starting | State::Running | State::Stopping)
    }

    pub fn name(&self) -> &str {
        match self {
            State::Starting => "starting",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Failed => "failed",
            State::Other(text) => text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    /// The Bus session on every request and grant from this instance.
    pub session: String,
    pub state: State,
    /// Runtime-written reason for `stopped` and `failed`; empty otherwise.
    pub cause: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub session: String,
    pub resource: String,
    pub action: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Granted,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Shell,
    Runtime,
}

/// A request with its terminal decision, readable by the shell (RI-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    pub request: Request,
    pub status: Status,
    /// The decision's reason; empty while pending.
    pub decision: String,
    pub settled_by: Option<Actor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveGrant {
    pub request_id: String,
    pub session: String,
    pub resource: String,
    pub action: String,
}

/// Every call is made by the harness as the shell. Errors are reasons.
pub trait ResidentRuntime {
    /// RI-2: returns while the instance is live.
    fn launch(&mut self, fixture: Fixture) -> Result<Instance, String>;
    /// RI-3.
    fn instances(&mut self) -> Result<Vec<Instance>, String>;
    /// RI-4.
    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String>;
    fn pending(&mut self) -> Result<Vec<Request>, String>;
    /// RI-5: every request of one session, pending or settled.
    fn requests(&mut self, session: &str) -> Result<Vec<RequestRecord>, String>;
    fn grant_session(&mut self, request_id: &str) -> Result<(), String>;
    fn deny(&mut self, request_id: &str, reason: &str) -> Result<(), String>;
    /// RI-7: every session's live grants.
    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String>;
    fn seed(&mut self, resource: &str, bytes: &[u8]) -> Result<(), String>;
    /// Operating-system processes below the Runtime process.
    fn processes(&mut self) -> Result<Vec<u32>, String>;
    fn healthy(&mut self) -> Result<(), String>;
    fn elapsed(&self) -> Duration;
    fn pause(&mut self);
}
