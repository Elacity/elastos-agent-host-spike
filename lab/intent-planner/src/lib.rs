#![forbid(unsafe_code)]

//! Lab model for M1 check A15.
//!
//! A local planner turns one intent into a typed plan. Each step names a
//! capability and a resource. The preview shows that plan. The host records
//! an allow-once grant for each step only when the person approves. Execution
//! then runs those steps with those grants.
//!
//! A rejected plan, a plan whose bytes changed after approval, a run list
//! that is not the approved list, and a second use of the same grant all
//! stop before any effect is recorded.
//!
//! This crate stands in for that gate. It does not mint a Runtime capability
//! token and it does not call a provider.

#[cfg(test)]
mod plant;

use std::fmt;

/// The actions the Runtime grant path accepts.
///
/// `handle_grant_capability` accepts `read`, `write`, `execute` and
/// `message`. This planner issues `read` and `write`. A caller can still
/// present `execute` at run time; the host then refuses it when that step
/// was not approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Execute,
    Message,
}

impl Action {
    /// The action name the Runtime grant path uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Execute => "execute",
            Action::Message => "message",
        }
    }
}

/// One capability: the Runtime action and the provider operation it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub action: Action,
    pub operation: String,
}

/// One planned step. The caller can change these fields. The host binds the
/// values it saw at approval time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub id: u32,
    pub capability: Capability,
    pub resource: String,
}

/// A typed plan for one intent and one agent principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub principal: String,
    pub intent: String,
    pub steps: Vec<Step>,
}

impl Plan {
    /// The exact bytes approval binds. Each field is length-prefixed, so a
    /// later edit cannot keep the same binding by moving a separator.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_field(&mut out, &self.principal);
        push_field(&mut out, &self.intent);
        push_field(&mut out, &self.steps.len().to_string());
        for step in &self.steps {
            push_field(&mut out, &step.id.to_string());
            push_field(&mut out, step.capability.action.as_str());
            push_field(&mut out, &step.capability.operation);
            push_field(&mut out, &step.resource);
        }
        out
    }
}

fn push_field(out: &mut String, field: &str) {
    out.push_str(&field.len().to_string());
    out.push(':');
    out.push_str(field);
    out.push('\n');
}

/// The person's decision on one preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Approve,
    Reject,
}

/// Why the host recorded no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
    BadPrincipal,
    UnknownIntent,
    NotApproved,
    PlanAltered,
    OutsidePlan,
    GrantSpent,
}

impl fmt::Display for Refuse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Refuse::BadPrincipal => "principal is not a single plain name",
            Refuse::UnknownIntent => "the planner has no steps for this intent",
            Refuse::NotApproved => "the plan was not approved",
            Refuse::PlanAltered => "the plan was altered after approval",
            Refuse::OutsidePlan => "a step is outside the approved plan",
            Refuse::GrantSpent => "the approved grant was already used",
        })
    }
}

/// The allow-once grant recorded for one approved step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    token: String,
    step_id: u32,
    action: Action,
    operation: String,
    resource: String,
}

impl Grant {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn step_id(&self) -> u32 {
        self.step_id
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    fn covers(&self, step: &Step) -> bool {
        self.step_id == step.id
            && self.action == step.capability.action
            && self.operation == step.capability.operation
            && self.resource == step.resource
    }
}

/// The decision recorded for one plan, plus the grants approval minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    choice: Choice,
    canonical: String,
    grants: Vec<Grant>,
}

impl Review {
    pub fn choice(&self) -> Choice {
        self.choice
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
}

/// One effect the host allowed. This is a record, not a provider call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub step_id: u32,
    pub action: Action,
    pub operation: String,
    pub resource: String,
    pub grant_token: String,
}

/// The lab host. It records reviews, grants and effects.
#[derive(Debug)]
pub struct Host {
    next_grant: u64,
    effects: Vec<Effect>,
    used: Vec<String>,
}

impl Host {
    pub fn new() -> Self {
        Self {
            next_grant: 0,
            effects: Vec::new(),
            used: Vec::new(),
        }
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// Records the person's choice. Approve mints one grant per step from the
    /// plan's current bytes. Reject mints none.
    pub fn review(&mut self, plan: &Plan, choice: Choice) -> Review {
        let grants = if choice == Choice::Approve {
            plan.steps.iter().map(|step| self.mint(step)).collect()
        } else {
            Vec::new()
        };
        Review {
            choice,
            canonical: plan.canonical(),
            grants,
        }
    }

    /// Runs `steps` when `review` approves this exact `plan` and `steps` is
    /// that approved list. Any other call leaves the effect list unchanged.
    pub fn execute(&mut self, review: &Review, plan: &Plan, steps: &[Step]) -> Result<(), Refuse> {
        let allowed = self.approval_check(review, plan, steps)?;
        for grant in &allowed {
            self.effects.push(Effect {
                step_id: grant.step_id,
                action: grant.action,
                operation: grant.operation.clone(),
                resource: grant.resource.clone(),
                grant_token: grant.token.clone(),
            });
            self.used.push(grant.token.clone());
        }
        Ok(())
    }

    fn mint(&mut self, step: &Step) -> Grant {
        self.next_grant += 1;
        Grant {
            token: format!("g{}", self.next_grant),
            step_id: step.id,
            action: step.capability.action,
            operation: step.capability.operation.clone(),
            resource: step.resource.clone(),
        }
    }

    fn approval_check(
        &self,
        review: &Review,
        plan: &Plan,
        steps: &[Step],
    ) -> Result<Vec<Grant>, Refuse> {
        if review.choice != Choice::Approve {
            return Err(Refuse::NotApproved);
        }
        if review.canonical != plan.canonical() {
            return Err(Refuse::PlanAltered);
        }
        if steps.len() != review.grants.len() {
            return Err(Refuse::OutsidePlan);
        }
        let mut allowed = Vec::with_capacity(steps.len());
        for (step, grant) in steps.iter().zip(review.grants.iter()) {
            if !grant.covers(step) {
                return Err(Refuse::OutsidePlan);
            }
            if self.used.contains(&grant.token) {
                return Err(Refuse::GrantSpent);
            }
            allowed.push(grant.clone());
        }
        Ok(allowed)
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

struct PlannedStep {
    action: Action,
    operation: &'static str,
    tail: &'static str,
}

/// Turns `intent` into a typed plan for `principal`.
///
/// The table is fixed. An intent outside the table is refused. No hosted
/// model is called.
pub fn plan(principal: &str, intent: &str) -> Result<Plan, Refuse> {
    if !plain_principal(principal) {
        return Err(Refuse::BadPrincipal);
    }
    let rows = planned(intent)?;
    let mut steps = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let id = u32::try_from(index + 1).expect("planned step id fits in u32");
        steps.push(Step {
            id,
            capability: Capability {
                action: row.action,
                operation: row.operation.to_owned(),
            },
            resource: format!("UsersAI/{principal}/{}", row.tail),
        });
    }
    Ok(Plan {
        principal: principal.to_owned(),
        intent: intent.to_owned(),
        steps,
    })
}

/// Renders the plan for the person. The text lists each step and records no grant.
pub fn preview(plan: &Plan) -> String {
    let mut text = String::new();
    text.push_str("Plan preview\n");
    text.push_str("Intent: ");
    text.push_str(&plan.intent);
    text.push('\n');
    text.push_str("Principal: ");
    text.push_str(&plan.principal);
    text.push('\n');
    text.push_str(
        "This preview shows the steps. A grant is recorded only when you approve this plan.\n",
    );
    for step in &plan.steps {
        text.push('\n');
        text.push_str("Step ");
        text.push_str(&step.id.to_string());
        text.push('\n');
        text.push_str("Capability: ");
        text.push_str(step.capability.action.as_str());
        text.push('\n');
        text.push_str("Operation: ");
        text.push_str(&step.capability.operation);
        text.push('\n');
        text.push_str("Resource: ");
        text.push_str(&step.resource);
        text.push('\n');
    }
    text
}

/// Agent id rule used for a task id: 1 to 64 bytes, `[a-z0-9][a-z0-9._-]*`,
/// and it does not end in `.`.
fn plain_principal(name: &str) -> bool {
    name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !name.ends_with('.')
}

fn planned(intent: &str) -> Result<&'static [PlannedStep], Refuse> {
    match intent {
        "summarize my notes into the journal" => Ok(&[
            PlannedStep {
                action: Action::Read,
                operation: "read",
                tail: "notes",
            },
            PlannedStep {
                action: Action::Write,
                operation: "append",
                tail: ".AppData/Agents/agent-host/journal",
            },
        ]),
        _ => Err(Refuse::UnknownIntent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTENT: &str = "summarize my notes into the journal";
    const PREVIEW: &str = "\
Plan preview
Intent: summarize my notes into the journal
Principal: ada
This preview shows the steps. A grant is recorded only when you approve this plan.

Step 1
Capability: read
Operation: read
Resource: UsersAI/ada/notes

Step 2
Capability: write
Operation: append
Resource: UsersAI/ada/.AppData/Agents/agent-host/journal
";

    fn sample() -> Plan {
        plan("ada", INTENT).expect("plan")
    }

    #[test]
    fn planner_lists_capability_and_resource_for_each_step() {
        let plan = sample();
        assert_eq!(Action::Execute.as_str(), "execute");
        assert_eq!(Action::Message.as_str(), "message");
        assert_eq!(plan.principal, "ada");
        assert_eq!(plan.intent, INTENT);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].id, 1);
        assert_eq!(plan.steps[0].capability.action, Action::Read);
        assert_eq!(plan.steps[0].capability.operation, "read");
        assert_eq!(plan.steps[0].resource, "UsersAI/ada/notes");
        assert_eq!(plan.steps[1].id, 2);
        assert_eq!(plan.steps[1].capability.action, Action::Write);
        assert_eq!(plan.steps[1].capability.operation, "append");
        assert_eq!(
            plan.steps[1].resource,
            "UsersAI/ada/.AppData/Agents/agent-host/journal"
        );
        assert_eq!(super::plan("ada", INTENT).expect("again"), plan);
        assert_eq!(preview(&plan), PREVIEW);

        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        assert_eq!(preview(&plan), PREVIEW);
        assert_eq!(review.grants().len(), 2);
        for grant in review.grants() {
            assert!(!PREVIEW.contains(grant.token()));
        }
    }

    #[test]
    fn approved_plan_executes_with_the_approved_grants() {
        let plan = sample();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        assert_eq!(review.choice(), Choice::Approve);
        host.execute(&review, &plan, &plan.steps).expect("run");
        assert_eq!(host.effects().len(), plan.steps.len());
        for (effect, grant) in host.effects().iter().zip(review.grants()) {
            assert_eq!(effect.step_id, grant.step_id());
            assert_eq!(effect.action, grant.action());
            assert_eq!(effect.operation, grant.operation());
            assert_eq!(effect.resource, grant.resource());
            assert_eq!(effect.grant_token, grant.token());
        }
        assert_eq!(host.effects()[0].resource, "UsersAI/ada/notes");
        assert_eq!(
            host.effects()[1].resource,
            "UsersAI/ada/.AppData/Agents/agent-host/journal"
        );
    }

    #[test]
    fn rejected_plan_executes_nothing() {
        let plan = sample();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Reject);
        assert_eq!(review.choice(), Choice::Reject);
        assert!(review.grants().is_empty());
        let error = host
            .execute(&review, &plan, &plan.steps)
            .expect_err("rejected");
        assert_eq!(error, Refuse::NotApproved);
        assert_eq!(error.to_string(), "the plan was not approved");
        assert!(host.effects().is_empty());
    }

    #[test]
    fn plan_altered_after_approval_is_refused() {
        let plan = sample();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        let mut altered = plan.clone();
        altered.steps[1].resource = "UsersAI/ada/secrets".to_owned();
        assert_ne!(plan.canonical(), altered.canonical());
        let error = host
            .execute(&review, &altered, &altered.steps)
            .expect_err("altered");
        assert_eq!(error, Refuse::PlanAltered);
        assert_eq!(error.to_string(), "the plan was altered after approval");
        assert!(host.effects().is_empty());
    }

    #[test]
    fn extra_step_injected_at_run_time_is_refused() {
        let plan = sample();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        let mut steps = plan.steps.clone();
        steps.push(Step {
            id: 3,
            capability: Capability {
                action: Action::Execute,
                operation: "run".to_owned(),
            },
            resource: "UsersAI/ada/Projects/build".to_owned(),
        });
        let error = host.execute(&review, &plan, &steps).expect_err("injected");
        assert_eq!(error, Refuse::OutsidePlan);
        assert_eq!(error.to_string(), "a step is outside the approved plan");
        assert!(host.effects().is_empty());
    }

    #[test]
    fn approved_grant_runs_once() {
        let plan = sample();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        host.execute(&review, &plan, &plan.steps).expect("once");
        let ran = host.effects().len();
        let error = host
            .execute(&review, &plan, &plan.steps)
            .expect_err("again");
        assert_eq!(error, Refuse::GrantSpent);
        assert_eq!(error.to_string(), "the approved grant was already used");
        assert_eq!(host.effects().len(), ran);
    }

    #[test]
    fn unknown_intent_and_bad_principal_are_refused() {
        assert_eq!(
            plan("ada", "delete my notes").unwrap_err(),
            Refuse::UnknownIntent
        );
        assert_eq!(
            plan("ada", "delete my notes").unwrap_err().to_string(),
            "the planner has no steps for this intent"
        );
        assert_eq!(plan("Ada", INTENT).unwrap_err(), Refuse::BadPrincipal);
        assert_eq!(plan("ada/other", INTENT).unwrap_err(), Refuse::BadPrincipal);
        assert_eq!(plan("", INTENT).unwrap_err(), Refuse::BadPrincipal);
        assert_eq!(plan("ada.", INTENT).unwrap_err(), Refuse::BadPrincipal);
        assert_eq!(
            plan("ada.", INTENT).unwrap_err().to_string(),
            "principal is not a single plain name"
        );
    }

    #[test]
    fn crate_has_no_dependencies_and_forbids_unsafe() {
        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("read Cargo.toml");
        assert!(!manifest.contains("[dependencies]"));
        assert!(!manifest.contains("[dev-dependencies]"));
        let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
            .expect("read src/lib.rs");
        assert!(
            lib.starts_with("#![forbid(unsafe_code)]"),
            "src/lib.rs must begin with forbid(unsafe_code)"
        );
    }

    #[test]
    fn model_planted_bugs_are_caught() {
        plant::run_all();
    }
}
