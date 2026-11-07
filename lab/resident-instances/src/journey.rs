//! The five journeys. Each starts from a healthy Runtime, launches its own
//! instances through the operator, decides their requests as the shell, and
//! ends with the cleanup census. A failed journey stops what it launched.
//!
//! Messages name instances by launch label (`instance-1`, `instance-2`);
//! instance ids, sessions and request ids stay in memory.

use std::time::Duration;

use crate::contract::{
    Actor, Fixture, Instance, LiveGrant, Request, RequestRecord, ResidentRuntime, State, Status,
    CANCEL_REASON, CLEANUP_REASON, DENY_REASON, READ_REASON, SHARED_BYTES, SHARED_RESOURCE,
};

/// Every awaited Runtime transition must land within this bound. It is a
/// third of the bridge's 30-second decision wait and far below the pending
/// store's 300-second expiry, so neither timeout can stand in for a settlement.
pub const STATE_BOUND: Duration = Duration::from_secs(10);
/// How long an ended instance is watched for a retry.
pub const WATCH: Duration = Duration::from_secs(2);
/// How long two instances must stay running after `start` returned.
pub const DWELL: Duration = Duration::from_secs(1);

pub type Outcome = Result<String, String>;

#[derive(Clone)]
struct Launched {
    label: String,
    id: String,
    session: String,
}

struct Journey<'r, R: ResidentRuntime> {
    rt: &'r mut R,
    launched: Vec<Launched>,
    decided: Vec<String>,
    baseline: Vec<u32>,
}

fn run<R: ResidentRuntime>(
    rt: &mut R,
    body: impl FnOnce(&mut Journey<'_, R>) -> Outcome,
) -> Outcome {
    let mut journey = Journey::begin(rt)?;
    body(&mut journey).map_err(|reason| {
        let note = journey.abandon();
        format!("{reason}{note}")
    })
}

fn listed<R: ResidentRuntime>(rt: &mut R, of: &Launched) -> Result<Option<Instance>, String> {
    let found: Vec<Instance> = rt
        .instances()?
        .into_iter()
        .filter(|instance| instance.id == of.id)
        .collect();
    match found.as_slice() {
        [] => Ok(None),
        [one] if one.session != of.session => Err(format!(
            "the instance list names another Bus session for {} than its launch did",
            of.label
        )),
        [one] => Ok(Some(one.clone())),
        _ => Err(format!("the instance list repeats {}", of.label)),
    }
}

fn fixture_request(request: &Request, of: &Launched) -> Result<(), String> {
    if request.resource != SHARED_RESOURCE
        || request.action != "read"
        || request.reason != READ_REASON
    {
        return Err(format!(
            "{} asked {} {} ({:?}); the fixture asks only read {} ({:?})",
            of.label,
            request.action,
            request.resource,
            request.reason,
            SHARED_RESOURCE,
            READ_REASON
        ));
    }
    Ok(())
}

impl<'r, R: ResidentRuntime> Journey<'r, R> {
    fn begin(rt: &'r mut R) -> Result<Self, String> {
        rt.healthy()?;
        rt.seed(SHARED_RESOURCE, SHARED_BYTES)?;
        // After the seed, so a provider the seed starts belongs to the baseline.
        let baseline = rt.processes()?;
        Ok(Self {
            rt,
            launched: Vec::new(),
            decided: Vec::new(),
            baseline,
        })
    }

    fn launch_pair(
        &mut self,
        first: Fixture,
        second: Fixture,
    ) -> Result<(Launched, Launched), String> {
        let a = self.launch(first)?;
        let b = self.launch(second)?;
        if a.id == b.id {
            return Err("two launches returned one instance id".to_owned());
        }
        if a.session == b.session {
            return Err("two instances share one Bus session".to_owned());
        }
        Ok((a, b))
    }

    fn launch(&mut self, fixture: Fixture) -> Result<Launched, String> {
        let label = format!("instance-{}", self.launched.len() + 1);
        let instance = self.rt.launch(fixture)?;
        if instance.id.is_empty() || instance.session.is_empty() {
            return Err(format!(
                "the launch of {label} ({}) returned no instance id or Bus session",
                fixture.name()
            ));
        }
        let launched = Launched {
            label,
            id: instance.id,
            session: instance.session,
        };
        self.launched.push(launched.clone());
        // A fixture may already have failed when the answer is built; overlap
        // is proven by the instance-list snapshots, not by this answer.
        if let State::Other(status) = &instance.state {
            return Err(format!(
                "the launch of {} ({}) returned {status}, which is not a resident instance status",
                launched.label,
                fixture.name()
            ));
        }
        Ok(launched)
    }

    fn wait<T>(
        &mut self,
        bound: Duration,
        what: &str,
        mut probe: impl FnMut(&mut R) -> Result<Option<T>, String>,
    ) -> Result<T, String> {
        let deadline = self.rt.elapsed() + bound;
        loop {
            if let Some(value) = probe(self.rt)? {
                return Ok(value);
            }
            if self.rt.elapsed() >= deadline {
                return Err(format!("{what}: not seen within {}s", bound.as_secs()));
            }
            self.rt.pause();
        }
    }

    fn wait_state(&mut self, of: &Launched, wanted: State) -> Result<Instance, String> {
        let what = format!("{} {}", of.label, wanted.name());
        self.wait(STATE_BOUND, &what, |rt| match listed(rt, of)? {
            None => Err(format!(
                "{} left the instance list before it was {}",
                of.label,
                wanted.name()
            )),
            Some(now) if now.state == wanted => Ok(Some(now)),
            Some(now) if !now.state.live() => Err(format!(
                "{} ended {} ({:?}) instead of {}",
                of.label,
                now.state.name(),
                now.cause,
                wanted.name()
            )),
            Some(_) => Ok(None),
        })
    }

    fn wait_request(&mut self, of: &Launched) -> Result<Request, String> {
        let what = format!("the pending read from {}", of.label);
        self.wait(STATE_BOUND, &what, |rt| {
            let mine: Vec<Request> = rt
                .pending()?
                .into_iter()
                .filter(|request| request.session == of.session)
                .collect();
            match mine.as_slice() {
                [] => match listed(rt, of)? {
                    Some(now) if now.state.live() => Ok(None),
                    Some(now) => Err(format!(
                        "{} ended {} ({:?}) before its request",
                        of.label,
                        now.state.name(),
                        now.cause
                    )),
                    None => Err(format!(
                        "{} left the instance list before its request",
                        of.label
                    )),
                },
                [one] => fixture_request(one, of).map(|()| Some(one.clone())),
                more => Err(format!(
                    "{} has {} pending requests; the fixture makes one",
                    of.label,
                    more.len()
                )),
            }
        })
    }

    fn grant(&mut self, request: &Request) -> Result<(), String> {
        self.decided.push(request.id.clone());
        self.rt.grant_session(&request.id)
    }

    fn deny(&mut self, request: &Request, reason: &str) -> Result<(), String> {
        self.decided.push(request.id.clone());
        self.rt.deny(&request.id, reason)
    }

    fn stop(&mut self, of: &Launched, reason: &str) -> Result<Instance, String> {
        self.rt.stop(&of.id, reason)?;
        let stopped = self.wait_state(of, State::Stopped)?;
        if !stopped.cause.contains(reason) {
            return Err(format!(
                "{} stopped with cause {:?}, which omits the stop reason {:?}",
                of.label, stopped.cause, reason
            ));
        }
        Ok(stopped)
    }

    fn still_pending(&mut self, request: &Request) -> Result<bool, String> {
        Ok(self.rt.pending()?.iter().any(|row| row == request))
    }

    /// One instance-list snapshot in which every named instance meets `wanted`.
    fn together(
        &mut self,
        of: &[&Launched],
        wanted: impl Fn(&State) -> bool,
        expected: &str,
        when: &str,
    ) -> Result<(), String> {
        let snapshot = self.rt.instances()?;
        for instance in of {
            match snapshot.iter().find(|now| now.id == instance.id) {
                Some(now) if wanted(&now.state) => {}
                Some(now) => {
                    return Err(format!(
                        "{} was {} {when}; expected {expected}",
                        instance.label,
                        now.state.name()
                    ))
                }
                None => {
                    return Err(format!(
                        "{} was absent from the instance list {when}",
                        instance.label
                    ))
                }
            }
        }
        Ok(())
    }

    fn sessions(&self) -> Vec<String> {
        self.launched.iter().map(|l| l.session.clone()).collect()
    }

    fn label_of(&self, session: &str) -> String {
        self.launched
            .iter()
            .find(|l| l.session == session)
            .map_or_else(|| "another session".to_owned(), |l| l.label.clone())
    }

    fn journey_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        let sessions = self.sessions();
        Ok(self
            .rt
            .live_grants()?
            .into_iter()
            .filter(|grant| sessions.contains(&grant.session))
            .collect())
    }

    fn only_grant(&mut self, of: &Launched, when: &str) -> Result<(), String> {
        let grants = self.journey_grants()?;
        match grants.as_slice() {
            [one]
                if one.session == of.session
                    && one.resource == SHARED_RESOURCE
                    && one.action == "read" =>
            {
                Ok(())
            }
            other => {
                let named: Vec<String> = other
                    .iter()
                    .map(|g| {
                        format!(
                            "{} {} for {}",
                            g.action,
                            g.resource,
                            self.label_of(&g.session)
                        )
                    })
                    .collect();
                Err(format!(
                    "live grants {when}: [{}]; expected one read grant bound to {}",
                    named.join(", "),
                    of.label
                ))
            }
        }
    }

    fn new_processes(&mut self) -> Result<Vec<u32>, String> {
        let baseline = self.baseline.clone();
        Ok(self
            .rt
            .processes()?
            .into_iter()
            .filter(|pid| !baseline.contains(pid))
            .collect())
    }

    /// The one request of an ended instance carries a Runtime denial whose
    /// reason names the end, and nothing from that instance is still pending.
    fn runtime_settlement(
        &mut self,
        of: &Launched,
        seen: Option<&Request>,
        mention: &str,
    ) -> Result<RequestRecord, String> {
        let what = format!("the Runtime's settlement of the request from {}", of.label);
        let record = self.wait(STATE_BOUND, &what, |rt| {
            let records = rt.requests(&of.session)?;
            match records.as_slice() {
                [] => Ok(None),
                [one] if one.status == Status::Pending => Ok(None),
                [one] => Ok(Some(one.clone())),
                more => Err(format!(
                    "{} has {} request records; the fixture makes one",
                    of.label,
                    more.len()
                )),
            }
        })?;
        if record.request.session != of.session {
            return Err(format!(
                "the request records for {} name another session",
                of.label
            ));
        }
        fixture_request(&record.request, of)?;
        if seen.is_some_and(|request| request.id != record.request.id) {
            return Err(format!(
                "the settled record for {} is not the request that was pending",
                of.label
            ));
        }
        if self.decided.contains(&record.request.id) {
            return Err(format!(
                "the harness decided the request from {}; this check needs the Runtime's own settlement",
                of.label
            ));
        }
        if record.status != Status::Denied {
            return Err(format!(
                "the request from {} ended {:?}; the Runtime must deny it when the instance ends",
                of.label, record.status
            ));
        }
        if record.settled_by != Some(Actor::Runtime) {
            return Err(format!(
                "the request from {} was settled by {:?}, not by the Runtime",
                of.label, record.settled_by
            ));
        }
        if mention.is_empty() || !record.decision.contains(mention) {
            return Err(format!(
                "the Runtime's denial for {} reads {:?}, which omits {:?}",
                of.label, record.decision, mention
            ));
        }
        if self.rt.pending()?.iter().any(|r| r.session == of.session) {
            return Err(format!("a request from {} is still pending", of.label));
        }
        Ok(record)
    }

    /// Over [`WATCH`], an ended instance makes no new request and stays ended.
    fn watch(&mut self, of: &Launched, ended: &State) -> Result<(), String> {
        let until = self.rt.elapsed() + WATCH;
        loop {
            if self.rt.pending()?.iter().any(|r| r.session == of.session) {
                return Err(format!("{} made a request after it ended", of.label));
            }
            let records = self.rt.requests(&of.session)?.len();
            if records != 1 {
                return Err(format!(
                    "{} has {records} request records after it ended; expected its one settled request",
                    of.label
                ));
            }
            match listed(self.rt, of)? {
                Some(now) if &now.state == ended => {}
                Some(now) => {
                    return Err(format!(
                        "{} changed from {} to {} after it ended",
                        of.label,
                        ended.name(),
                        now.state.name()
                    ))
                }
                None => {
                    return Err(format!(
                        "{} left the instance list inside the watch; its final record must stay readable",
                        of.label
                    ))
                }
            }
            if self.rt.elapsed() >= until {
                return Ok(());
            }
            self.rt.pause();
        }
    }

    fn census(&mut self, grants: bool) -> Result<String, String> {
        let snapshot = self.rt.instances()?;
        for launched in &self.launched {
            if let Some(now) = snapshot
                .iter()
                .find(|now| now.id == launched.id && now.state.live())
            {
                return Err(format!(
                    "instance leftover: {} is {}",
                    launched.label,
                    now.state.name()
                ));
            }
        }
        let sessions = self.sessions();
        if let Some(request) = self
            .rt
            .pending()?
            .into_iter()
            .find(|request| sessions.contains(&request.session))
        {
            return Err(format!(
                "pending request leftover from {}",
                self.label_of(&request.session)
            ));
        }
        let grant_text = if grants {
            if let Some(grant) = self.journey_grants()?.first() {
                return Err(format!(
                    "live grant leftover: {} {} for {}",
                    grant.action,
                    grant.resource,
                    self.label_of(&grant.session)
                ));
            }
            "0"
        } else {
            "not checked here (RI-7; A6 and A12 check them)"
        };
        let new = self.new_processes()?;
        if !new.is_empty() {
            return Err(format!(
                "process leftover: {} new processes below the Runtime",
                new.len()
            ));
        }
        self.rt.healthy()?;
        Ok(format!(
            "census: live instances 0, pending requests 0, live grants {grant_text}, new processes 0, Runtime healthy"
        ))
    }

    /// Stop whatever this journey left live; the failure reason stays first.
    fn abandon(&mut self) -> String {
        let mut failures = Vec::new();
        for launched in self.launched.clone() {
            let live = match listed(self.rt, &launched) {
                Ok(Some(now)) => now.state.live(),
                Ok(None) => false,
                Err(_) => true,
            };
            if live {
                if let Err(reason) = self.rt.stop(&launched.id, CLEANUP_REASON) {
                    failures.push(format!("{}: {reason}", launched.label));
                }
            }
        }
        if failures.is_empty() {
            String::new()
        } else {
            format!("; the cleanup stop also failed: {}", failures.join(", "))
        }
    }
}

/// A3: two instances of one capsule are resident together inside the one
/// Runtime, each with its own instance id and Bus session.
pub fn a3_two_resident_instances<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::ReadShared, Fixture::ReadShared)?;
        let ra = j.wait_request(&a)?;
        let rb = j.wait_request(&b)?;
        j.together(
            &[&a, &b],
            State::live,
            "live",
            "while both requests were pending",
        )?;
        j.grant(&ra)?;
        j.grant(&rb)?;
        j.wait_state(&a, State::Running)?;
        j.wait_state(&b, State::Running)?;
        let since = j.rt.elapsed();
        while j.rt.elapsed() < since + DWELL {
            j.rt.pause();
        }
        j.together(
            &[&a, &b],
            |state| *state == State::Running,
            "running",
            "after start returned and the dwell passed",
        )?;
        let new = j.new_processes()?;
        if !new.is_empty() {
            return Err(format!(
                "the two instances added {} processes below the Runtime; resident instances run inside it",
                new.len()
            ));
        }
        j.stop(&a, CLEANUP_REASON)?;
        j.stop(&b, CLEANUP_REASON)?;
        let census = j.census(false)?;
        Ok(format!(
            "A3: two instances of one capsule in one Runtime, two Bus sessions, both running {}s after start returned, no new processes; {census}",
            DWELL.as_secs()
        ))
    })
}

/// A6: a grant binds to the instance that asked. The sibling's request for the
/// same resource stays its own pending request while that grant is live.
pub fn a6_separate_grants<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::ReadShared, Fixture::ReadShared)?;
        let ra = j.wait_request(&a)?;
        let rb = j.wait_request(&b)?;
        j.grant(&ra)?;
        j.wait_state(&a, State::Running)?;
        j.only_grant(&a, "after instance-1's grant")?;
        if !j.still_pending(&rb)? {
            return Err(format!(
                "the request from {} for the same resource left the pending list while the grant of {} was live; a grant binds to its own instance",
                b.label, a.label
            ));
        }
        j.deny(&rb, DENY_REASON)?;
        let denied = j.wait_state(&b, State::Failed)?;
        if !denied.cause.contains(DENY_REASON) {
            return Err(format!(
                "{} failed with cause {:?}, which omits the denial {:?}",
                b.label, denied.cause, DENY_REASON
            ));
        }
        j.together(
            &[&a],
            |state| *state == State::Running,
            "running",
            "after the sibling's denial",
        )?;
        j.only_grant(&a, "after the sibling's denial")?;
        j.stop(&a, CLEANUP_REASON)?;
        let census = j.census(true)?;
        Ok(format!(
            "A6: instance-1 got a session grant and ran; the request from instance-2 for the same resource stayed its own pending request, and its denial reached it; live grants named only instance-1; {census}"
        ))
    })
}

/// A10: stopping one instance mid-request ends it and its request; the
/// sibling keeps its own request and runs on.
pub fn a10_cancel_one_instance<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::ReadShared, Fixture::ReadShared)?;
        let ra = j.wait_request(&a)?;
        let rb = j.wait_request(&b)?;
        j.stop(&a, CANCEL_REASON)?;
        j.runtime_settlement(&a, Some(&ra), CANCEL_REASON)?;
        j.together(&[&b], State::live, "live", "after instance-1 was cancelled")?;
        if !j.still_pending(&rb)? {
            return Err(format!(
                "the pending request from {} was settled when {} was cancelled",
                b.label, a.label
            ));
        }
        j.grant(&rb)?;
        j.wait_state(&b, State::Running)?;
        j.watch(&a, &State::Stopped)?;
        j.together(
            &[&b],
            |state| *state == State::Running,
            "running",
            "after the watch",
        )?;
        j.stop(&b, CLEANUP_REASON)?;
        let census = j.census(false)?;
        Ok(format!(
            "A10: instance-1 stopped mid-request with the cancel reason; the Runtime denied its pending request naming the stop; no request from it for {}s; instance-2 kept its own request, got its grant and kept running; {census}",
            WATCH.as_secs()
        ))
    })
}

/// A11: an instance that fails with a request pending has that request
/// settled by the Runtime; the sibling is unaffected.
pub fn a11_failed_instance_settled<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::FailAfterSubmit, Fixture::ReadShared)?;
        let failed = j.wait_state(&a, State::Failed)?;
        if failed.cause.is_empty() {
            return Err(format!("{} failed with no cause", a.label));
        }
        j.runtime_settlement(&a, None, &failed.cause)?;
        let rb = j.wait_request(&b)?;
        j.grant(&rb)?;
        j.wait_state(&b, State::Running)?;
        j.watch(&a, &State::Failed)?;
        j.stop(&b, CLEANUP_REASON)?;
        let census = j.census(false)?;
        Ok(format!(
            "A11: instance-1 failed ({:?}) with its request pending; the Runtime denied that request naming the failure; no request from it for {}s; instance-2 got its own grant and ran; {census}",
            failed.cause,
            WATCH.as_secs()
        ))
    })
}

/// A12: after both instances stop, nothing of theirs is left: no live
/// instance, pending request, live grant or process.
pub fn a12_cleanup_census<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::ReadShared, Fixture::ReadShared)?;
        let ra = j.wait_request(&a)?;
        let rb = j.wait_request(&b)?;
        j.grant(&ra)?;
        j.grant(&rb)?;
        j.wait_state(&a, State::Running)?;
        j.wait_state(&b, State::Running)?;
        let grants = j.journey_grants()?;
        let sees = |of: &Launched| grants.iter().any(|g| g.session == of.session);
        if !sees(&a) || !sees(&b) {
            return Err(format!(
                "the live-grant view showed {} grants for the two running instances; the census must see both before it can prove they end",
                grants.len()
            ));
        }
        j.stop(&a, CLEANUP_REASON)?;
        j.stop(&b, CLEANUP_REASON)?;
        let census = j.census(true)?;
        Ok(format!(
            "A12: before the stops the census saw 2 pending requests and {} live grants; after both stops {census}",
            grants.len()
        ))
    })
}
