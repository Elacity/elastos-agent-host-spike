//! A reference double of the SPEC.md interface, for harness self-tests only.
//! It is not the Runtime and counts toward no M1 check. Each fault switch
//! makes it behave like one wrong Runtime, so a journey can be shown to
//! refuse that behaviour for the expected reason.

use std::time::Duration;

use resident_instances::contract::{
    Actor, Fixture, Instance, LiveGrant, Request, RequestRecord, ResidentRuntime, State, Status,
    READ_REASON, SHARED_BYTES, SHARED_RESOURCE,
};

#[derive(Clone, Copy, Default)]
pub struct Faults {
    /// Launch answers after the run, as `POST /api/capsules` does today.
    pub launch_completes: bool,
    pub shared_session: bool,
    /// An instance leaves `running` 500 ms after `start` returned.
    pub brief_residency: bool,
    pub process_per_instance: bool,
    /// A live grant also satisfies other instances' requests for the resource.
    pub grant_covers_siblings: bool,
    pub stop_ignored: bool,
    pub stop_stops_all: bool,
    pub stop_drops_reason: bool,
    pub stop_leaves_pending: bool,
    /// The Runtime's denial of an ended instance's request gives no reason.
    pub settlement_drops_reason: bool,
    pub stop_keeps_grants: bool,
    pub process_leak_on_stop: bool,
    /// A stopped instance asks again 500 ms after its stop.
    pub retry_after_stop: bool,
    pub failure_leaves_pending: bool,
    pub shell_settles_failure: bool,
    pub blind_grant_census: bool,
}

const BASE_PROCESSES: [u32; 2] = [500, 501];
const TRAP: &str = "wasm trap: wasm `unreachable` instruction executed";
const STEP: Duration = Duration::from_millis(50);
const LATER: Duration = Duration::from_millis(500);

struct Slot {
    instance: Instance,
    pid: Option<u32>,
    leaves_at: Option<Duration>,
}

pub struct Double {
    faults: Faults,
    clock: Duration,
    next: u32,
    slots: Vec<Slot>,
    records: Vec<RequestRecord>,
    grants: Vec<LiveGrant>,
    seeded: Vec<u8>,
    leaked: Vec<u32>,
    retries: Vec<(String, Duration)>,
}

impl Double {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            clock: Duration::ZERO,
            next: 0,
            slots: Vec::new(),
            records: Vec::new(),
            grants: Vec::new(),
            seeded: Vec::new(),
            leaked: Vec::new(),
            retries: Vec::new(),
        }
    }

    pub fn live_instances(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.instance.state.live())
            .count()
    }

    fn index_of_session(&self, session: &str) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.instance.session == session && slot.instance.state.live())
    }

    fn submit(&mut self, session: &str) -> String {
        let id = format!("request-{}", self.records.len() + 1);
        self.records.push(RequestRecord {
            request: Request {
                id: id.clone(),
                session: session.to_owned(),
                resource: SHARED_RESOURCE.to_owned(),
                action: "read".to_owned(),
                reason: READ_REASON.to_owned(),
            },
            status: Status::Pending,
            decision: String::new(),
            settled_by: None,
        });
        id
    }

    fn settle(&mut self, session: &str, decision: &str, actor: Actor) {
        for record in &mut self.records {
            if record.request.session == session && record.status == Status::Pending {
                record.status = Status::Denied;
                record.decision = decision.to_owned();
                record.settled_by = Some(actor);
            }
        }
    }

    /// The fixture's read after its grant: start returns and it stays resident.
    fn read_and_return(&mut self, session: &str) {
        let Some(index) = self.index_of_session(session) else {
            return;
        };
        let bytes_match = self.seeded == SHARED_BYTES;
        let leaves_at = self.faults.brief_residency.then_some(self.clock + LATER);
        let slot = &mut self.slots[index];
        if bytes_match {
            slot.instance.state = State::Running;
            slot.leaves_at = leaves_at;
        } else {
            slot.instance.state = State::Failed;
            slot.instance.cause = "start returned: the read bytes differ".to_owned();
            slot.pid = None;
        }
    }

    fn approve(&mut self, request_id: &str, actor: Actor) -> Result<(), String> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.request.id == request_id && r.status == Status::Pending)
            .ok_or("HTTP 400: no such pending request")?;
        record.status = Status::Granted;
        record.decision = "granted".to_owned();
        record.settled_by = Some(actor);
        let request = record.request.clone();
        if actor == Actor::Shell {
            self.grants.push(LiveGrant {
                request_id: request.id.clone(),
                session: request.session.clone(),
                resource: request.resource.clone(),
                action: request.action.clone(),
            });
        }
        self.read_and_return(&request.session);
        if self.faults.grant_covers_siblings && actor == Actor::Shell {
            let siblings: Vec<String> = self
                .records
                .iter()
                .filter(|r| r.status == Status::Pending && r.request.resource == request.resource)
                .map(|r| r.request.id.clone())
                .collect();
            for sibling in siblings {
                self.approve(&sibling, Actor::Runtime)?;
            }
        }
        Ok(())
    }

    fn end(&mut self, index: usize, state: State, cause: String, decision: String, settle: bool) {
        let session = self.slots[index].instance.session.clone();
        let slot = &mut self.slots[index];
        slot.instance.state = state;
        slot.instance.cause = cause;
        slot.pid = None;
        slot.leaves_at = None;
        if settle {
            let actor =
                if self.faults.shell_settles_failure && decision.starts_with("instance failed") {
                    Actor::Shell
                } else {
                    Actor::Runtime
                };
            let decision = if self.faults.settlement_drops_reason {
                "denied"
            } else {
                decision.as_str()
            };
            self.settle(&session, decision, actor);
        }
        if !self.faults.stop_keeps_grants {
            self.grants.retain(|grant| grant.session != session);
        }
    }
}

impl ResidentRuntime for Double {
    fn launch(&mut self, fixture: Fixture) -> Result<Instance, String> {
        self.next += 1;
        let n = self.next;
        let session = if self.faults.shared_session {
            "session-shared".to_owned()
        } else {
            format!("session-{n}")
        };
        self.slots.push(Slot {
            instance: Instance {
                id: format!("instance-{n}"),
                session: session.clone(),
                state: State::Starting,
                cause: String::new(),
            },
            pid: self.faults.process_per_instance.then_some(9000 + n),
            leaves_at: None,
        });
        let index = self.slots.len() - 1;
        let request = self.submit(&session);
        match fixture {
            Fixture::ReadShared => {
                let covered = self.faults.grant_covers_siblings
                    && self
                        .grants
                        .iter()
                        .any(|g| g.resource == SHARED_RESOURCE && g.action == "read");
                if covered {
                    self.approve(&request, Actor::Runtime)?;
                }
            }
            Fixture::FailAfterSubmit => {
                let settle = !self.faults.failure_leaves_pending;
                self.end(
                    index,
                    State::Failed,
                    TRAP.to_owned(),
                    format!("instance failed: {TRAP}"),
                    settle,
                );
            }
        }
        let mut answer = self.slots[index].instance.clone();
        if self.faults.launch_completes {
            answer.state = State::Other("completed".to_owned());
        }
        Ok(answer)
    }

    fn instances(&mut self) -> Result<Vec<Instance>, String> {
        Ok(self
            .slots
            .iter()
            .map(|slot| slot.instance.clone())
            .collect())
    }

    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.instance.id == id)
            .ok_or("HTTP 404: no such instance")?;
        if self.faults.stop_ignored {
            return Ok(());
        }
        let targets: Vec<usize> = (0..self.slots.len())
            .filter(|t| {
                (self.faults.stop_stops_all || *t == index) && self.slots[*t].instance.state.live()
            })
            .collect();
        for target in targets {
            let cause = if self.faults.stop_drops_reason {
                "stopped".to_owned()
            } else {
                format!("stopped: {reason}")
            };
            let settle = !self.faults.stop_leaves_pending;
            self.end(
                target,
                State::Stopped,
                cause,
                format!("instance stopped: {reason}"),
                settle,
            );
            if self.faults.process_leak_on_stop {
                self.leaked.push(7000 + target as u32);
            }
            if self.faults.retry_after_stop {
                let session = self.slots[target].instance.session.clone();
                self.retries.push((session, self.clock + LATER));
            }
        }
        Ok(())
    }

    fn pending(&mut self) -> Result<Vec<Request>, String> {
        Ok(self
            .records
            .iter()
            .filter(|r| r.status == Status::Pending)
            .map(|r| r.request.clone())
            .collect())
    }

    fn requests(&mut self, session: &str) -> Result<Vec<RequestRecord>, String> {
        Ok(self
            .records
            .iter()
            .filter(|r| r.request.session == session)
            .cloned()
            .collect())
    }

    fn grant_session(&mut self, request_id: &str) -> Result<(), String> {
        self.approve(request_id, Actor::Shell)
    }

    fn deny(&mut self, request_id: &str, reason: &str) -> Result<(), String> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.request.id == request_id && r.status == Status::Pending)
            .ok_or("HTTP 400: no such pending request")?;
        record.status = Status::Denied;
        record.decision = reason.to_owned();
        record.settled_by = Some(Actor::Shell);
        let session = record.request.session.clone();
        if let Some(index) = self.index_of_session(&session) {
            let slot = &mut self.slots[index];
            slot.instance.state = State::Failed;
            slot.instance.cause = format!("start returned Denied({reason:?})");
            slot.pid = None;
        }
        Ok(())
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        if self.faults.blind_grant_census {
            return Ok(Vec::new());
        }
        Ok(self.grants.clone())
    }

    fn seed(&mut self, resource: &str, bytes: &[u8]) -> Result<(), String> {
        if resource == SHARED_RESOURCE {
            self.seeded = bytes.to_vec();
        }
        Ok(())
    }

    fn processes(&mut self) -> Result<Vec<u32>, String> {
        let mut pids: Vec<u32> = BASE_PROCESSES.to_vec();
        pids.extend(self.slots.iter().filter_map(|slot| slot.pid));
        pids.extend(&self.leaked);
        Ok(pids)
    }

    fn healthy(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn elapsed(&self) -> Duration {
        self.clock
    }

    fn pause(&mut self) {
        self.clock += STEP;
        let now = self.clock;
        for slot in &mut self.slots {
            if slot.leaves_at.is_some_and(|at| at <= now) && slot.instance.state == State::Running {
                slot.instance.state = State::Stopped;
                slot.instance.cause = "lifecycle returned".to_owned();
                slot.pid = None;
                slot.leaves_at = None;
            }
        }
        let due: Vec<String> = self
            .retries
            .iter()
            .filter(|(_, at)| *at <= now)
            .map(|(session, _)| session.clone())
            .collect();
        self.retries.retain(|(_, at)| *at > now);
        for session in due {
            self.submit(&session);
        }
    }
}
