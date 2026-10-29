//! M1 check A3: two agent components are resident at once.
//!
//! The journey enters only through the stand-in routes: `post_capsules`,
//! `finish_start`, `get_capsules` and `delete_capsule`. It proves that two
//! admitted bundles launch as two separate resident instances with distinct
//! ids, that the list shows both running, and that stopping one leaves the
//! other running. The stub case runs the same checks over a hosting stand-in
//! that answers `Ok` without making the instance resident: the checks fail it.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::SignedBundle;

const AGENT_A_NAME: &str = "agent-a";
const AGENT_B_NAME: &str = "agent-b";
const STOP_ONE: &str = "stop one";

/// One admitted row, kept beside the bundle that carries it.
fn admit(standin: &mut StandIn, bundle: &SignedBundle) {
    standin
        .admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed agent bundle");
}

/// Launches one admitted bundle through `post_capsules` and returns the id
/// the launch answer names.
fn launch(standin: &mut StandIn, bundle: &SignedBundle) -> Result<String, String> {
    let launched = standin
        .post_capsules(Caller::Shell, &bundle.launch_body())
        .map_err(|(status, reason)| format!("launch refused {status}: {reason}"))?;
    launched["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("the launch answer names no instance: {launched}"))
}

/// The shell list entry for `id`, or `None` when the list does not name it.
fn entry(standin: &StandIn, id: &str) -> Result<Option<Value>, String> {
    let listed = standin
        .get_capsules(Caller::Shell)
        .map_err(|(status, reason)| format!("list refused {status}: {reason}"))?;
    Ok(listed["capsules"]
        .as_array()
        .ok_or("the list answer holds no capsule array")?
        .iter()
        .find(|entry| entry["id"] == json!(id))
        .cloned())
}

/// One named entry with the wanted status, its manifest name and a session of
/// its own.
fn expect_live(found: Option<Value>, id: &str, name: &str, status: &str) -> Result<(), String> {
    let found = found.ok_or_else(|| format!("{id} is not listed"))?;
    if found["status"] != json!(status) {
        return Err(format!("{id} is not {status}: {found}"));
    }
    if found["name"] != json!(name) {
        return Err(format!("{id} is named {} not {name}", found["name"]));
    }
    if found["session_id"] != json!(id) {
        return Err(format!("{id} has no session of its own: {found}"));
    }
    Ok(())
}

/// The A3 check, run over one host's route answers.
///
/// `Ok(())` means two agent components are resident at once under distinct
/// ids, and one stop leaves the other running.
fn check<H>(host: &mut H) -> Result<(), String>
where
    H: Hosting,
{
    let first = host.launch(AGENT_A_NAME)?;
    let second = host.launch(AGENT_B_NAME)?;
    if first == second {
        return Err(format!("both launches reuse one id: {first}"));
    }
    expect_live(host.entry(&first)?, &first, AGENT_A_NAME, "starting")?;
    expect_live(host.entry(&second)?, &second, AGENT_B_NAME, "starting")?;
    host.finish_start(&first)?;
    host.finish_start(&second)?;
    expect_live(host.entry(&first)?, &first, AGENT_A_NAME, "running")?;
    expect_live(host.entry(&second)?, &second, AGENT_B_NAME, "running")?;
    let survivor = host.entry(&second)?;
    host.stop(&first, STOP_ONE)?;
    let stopped = host
        .entry(&first)?
        .ok_or_else(|| format!("{first} left the list after it stopped"))?;
    if stopped["status"] != "stopped" || stopped["cause"] != json!(format!("stopped: {STOP_ONE}")) {
        return Err(format!("{first} is not stopped with its cause: {stopped}"));
    }
    if host.entry(&second)? != survivor {
        return Err(format!("the sibling stop changed {second}"));
    }
    expect_live(host.entry(&second)?, &second, AGENT_B_NAME, "running")
}

/// The route answers the A3 check reads, by the manifest name of each agent.
trait Hosting {
    fn launch(&mut self, name: &str) -> Result<String, String>;
    fn finish_start(&mut self, id: &str) -> Result<(), String>;
    fn entry(&self, id: &str) -> Result<Option<Value>, String>;
    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String>;
}

/// The stand-in routes for the two admitted agent bundles.
struct Routes {
    standin: StandIn,
    agent_a: SignedBundle,
    agent_b: SignedBundle,
}

impl Routes {
    fn new() -> Self {
        let agent_a = SignedBundle::distinct(AGENT_A_NAME);
        let agent_b = SignedBundle::distinct(AGENT_B_NAME);
        assert_ne!(
            (agent_a.cid(), agent_a.path()),
            (agent_b.cid(), agent_b.path()),
            "the two agent bundles are two real bundles with two lab CIDs"
        );
        let mut standin = StandIn::new();
        admit(&mut standin, &agent_a);
        admit(&mut standin, &agent_b);
        Routes {
            standin,
            agent_a,
            agent_b,
        }
    }
}

impl Hosting for Routes {
    fn launch(&mut self, name: &str) -> Result<String, String> {
        let bundle = if name == AGENT_A_NAME {
            &self.agent_a
        } else {
            &self.agent_b
        };
        launch(&mut self.standin, bundle)
    }

    fn finish_start(&mut self, id: &str) -> Result<(), String> {
        self.standin
            .finish_start(id)
            .map_err(|(status, reason)| format!("start refused {status}: {reason}"))
    }

    fn entry(&self, id: &str) -> Result<Option<Value>, String> {
        entry(&self.standin, id)
    }

    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.standin
            .delete_capsule(Caller::Shell, id, &json!({ "reason": reason }))
            .map(|_| ())
            .map_err(|(status, refused)| format!("stop refused {status}: {refused}"))
    }
}

/// The stub hosting stand-in: it answers `Ok` to every call, names a fresh
/// id on each launch without making that instance resident, and lists an
/// empty pair. It holds no admission and no instance.
struct HostingStub {
    launches: usize,
}

impl Hosting for HostingStub {
    fn launch(&mut self, _name: &str) -> Result<String, String> {
        self.launches += 1;
        Ok(format!("stub-{}", self.launches))
    }

    fn finish_start(&mut self, _id: &str) -> Result<(), String> {
        Ok(())
    }

    fn entry(&self, _id: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }

    fn stop(&mut self, _id: &str, _reason: &str) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn two_agent_components_are_resident_at_once_through_the_routes() {
    let mut routes = Routes::new();
    check(&mut routes).expect("two agent components run at once as separate resident instances");
    let listed = routes
        .standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the shell capsule list");
    assert_eq!(
        listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .len(),
        2,
        "the stand-in lists the stopped entry and the surviving one"
    );
}

#[test]
fn an_ok_start_that_makes_no_instance_resident_fails_the_check() {
    let refused = check(&mut HostingStub { launches: 0 });
    assert!(
        matches!(&refused, Err(reason) if reason == "stub-1 is not listed"),
        "the A3 check fails a hosting stub that starts nothing: {refused:?}"
    );
}
