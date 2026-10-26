#![forbid(unsafe_code)]

//! Lab model for M1 check A15.
//!
//! A local planner turns one intent into a typed plan. Each step names a
//! capability and a resource. The preview shows that plan. Approval mints a
//! lab `CapabilityManager` token for each step the Runtime can name. Execution
//! sends that token through in-process
//! `handle_remote_request_with_audit_dir`. That is not a spawned Runtime
//! process.
//!
//! A rejected plan, a plan whose bytes changed after approval, a run list
//! that is not the approved ordered list, a review from another Host, and a
//! second use of the same grant all stop before a bridge call. A step the
//! Runtime cannot express is BLOCKED with the missing capability. The public
//! entry does not store a journal.

#[cfg(test)]
mod plant;

mod runtime_bridge;

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
    ForeignHost,
    Bridge,
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
            Refuse::ForeignHost => "the review was minted by another host",
            Refuse::Bridge => "the bus bridge did not answer",
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

    pub fn covers(&self, step: &Step) -> bool {
        self.step_id == step.id
            && self.action == step.capability.action
            && self.operation == step.capability.operation
            && self.resource == step.resource
    }
}

/// The decision recorded for one plan, plus the grants approval minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    host_id: String,
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

/// How one step ended. A blocked step names the capability the Runtime lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectKind {
    /// The public bus bridge refused the step before storage.
    Denied { code: String, message: String },
    /// The Runtime cannot perform the step. `missing` is that capability.
    Blocked { missing: String, code: String },
}

/// One step the host presented to the Runtime, or refused to present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub step_id: u32,
    pub action: Action,
    pub operation: String,
    pub resource: String,
    pub grant_token: String,
    pub kind: EffectKind,
}

/// The lab host. It records the person's decision and calls the in-process
/// bus entry. Each Host has its own lab `CapabilityManager` and audit dir.
#[derive(Debug)]
pub struct Host {
    id: String,
    grants: runtime_bridge::Grants,
    effects: Vec<Effect>,
    used: Vec<String>,
    audit: tempfile::TempDir,
}

impl Host {
    pub fn new() -> Self {
        Self {
            id: new_host_id(),
            grants: runtime_bridge::Grants::new(),
            effects: Vec::new(),
            used: Vec::new(),
            audit: tempfile::TempDir::new().expect("lab audit dir"),
        }
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// Directory that records in-process bus audit events for this Host.
    pub fn audit_dir(&self) -> &std::path::Path {
        self.audit.path()
    }

    /// Lab `CapabilityManager::validate` for a journal write token.
    pub fn validate_journal_write(&self, token: &str, resource: &str) -> Result<(), String> {
        self.grants.validate_journal_write(token, resource)
    }

    /// Records the person's choice. Approve mints one lab token for each
    /// step the Runtime can name. Reject mints none. A blocked step gets no token.
    pub fn review(&mut self, plan: &Plan, choice: Choice) -> Review {
        let grants = if choice == Choice::Approve {
            plan.steps
                .iter()
                .filter(|step| runtime_gap(step).is_none())
                .map(|step| self.mint(step))
                .collect()
        } else {
            Vec::new()
        };
        Review {
            host_id: self.id.clone(),
            choice,
            canonical: plan.canonical(),
            grants,
        }
    }

    /// Runs `steps` when `review` approves this exact `plan` and `steps` is
    /// that approved ordered list. A refused call leaves the effect list
    /// unchanged.
    pub fn execute(&mut self, review: &Review, plan: &Plan, steps: &[Step]) -> Result<(), Refuse> {
        let allowed = self.approval_check(review, plan, steps)?;
        let mut recorded = Vec::new();
        let mut spent = Vec::new();
        for step in steps {
            if let Some(missing) = runtime_gap(step) {
                recorded.push(Effect {
                    step_id: step.id,
                    action: step.capability.action,
                    operation: step.capability.operation.clone(),
                    resource: step.resource.clone(),
                    grant_token: String::new(),
                    kind: EffectKind::Blocked {
                        missing: missing.to_owned(),
                        code: String::new(),
                    },
                });
                continue;
            }
            let grant = grant_that_covers(&allowed, step)?;
            let agent = plan_agent(&step.resource);
            self.grants
                .validate_journal_write(&grant.token, &runtime_bridge::scoped_journal(agent))
                .map_err(|_| Refuse::Bridge)?;
            let reply = runtime_bridge::invoke_journal(
                &grant.token,
                &step.resource,
                Some(self.audit.path()),
            )
            .map_err(|_| Refuse::Bridge)?;
            let kind = match runtime_bridge::classify(&reply) {
                runtime_bridge::BridgeClass::StorageBlocked => EffectKind::Blocked {
                    missing: runtime_bridge::STORAGE_BRIDGE_GAP.to_owned(),
                    code: reply.code,
                },
                runtime_bridge::BridgeClass::Unapproved | runtime_bridge::BridgeClass::Other => {
                    EffectKind::Denied {
                        code: reply.code,
                        message: reply.message,
                    }
                }
            };
            recorded.push(Effect {
                step_id: step.id,
                action: step.capability.action,
                operation: step.capability.operation.clone(),
                resource: step.resource.clone(),
                grant_token: grant.token.clone(),
                kind,
            });
            spent.push(grant.token.clone());
        }
        self.effects.extend(recorded);
        self.used.extend(spent);
        Ok(())
    }

    fn mint(&self, step: &Step) -> Grant {
        let agent = plan_agent(&step.resource);
        Grant {
            token: self.grants.mint_journal_write(agent),
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
        if review.host_id != self.id {
            return Err(Refuse::ForeignHost);
        }
        if review.choice != Choice::Approve {
            return Err(Refuse::NotApproved);
        }
        if review.canonical != plan.canonical() {
            return Err(Refuse::PlanAltered);
        }
        if steps != plan.steps.as_slice() {
            return Err(Refuse::OutsidePlan);
        }
        let mut allowed = Vec::new();
        for step in steps {
            if runtime_gap(step).is_some() {
                continue;
            }
            let grant = grant_that_covers(&review.grants, step)?;
            if self.used.contains(&grant.token) {
                return Err(Refuse::GrantSpent);
            }
            allowed.push(grant.clone());
        }
        Ok(allowed)
    }
}

fn new_host_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("host-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn grant_that_covers<'a>(grants: &'a [Grant], step: &Step) -> Result<&'a Grant, Refuse> {
    grants
        .iter()
        .find(|grant| grant.covers(step))
        .ok_or(Refuse::OutsidePlan)
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

struct PlannedStep {
    action: Action,
    operation: &'static str,
    journal: bool,
}

/// The Runtime gap for a step it cannot name, if there is one.
pub fn runtime_gap(step: &Step) -> Option<&'static str> {
    if step
        .resource
        .starts_with("localhost://Users/self/.AppData/Agents/")
        && step.capability.action == Action::Write
        && step.capability.operation == "write"
    {
        None
    } else if step.resource.starts_with("localhost://UsersAI/") {
        Some(runtime_bridge::USERS_AI_GAP)
    } else {
        Some("resource is outside the journal bridge")
    }
}

fn plan_agent(resource: &str) -> &str {
    resource
        .split("/.AppData/Agents/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
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
            resource: if row.journal {
                runtime_bridge::guest_journal(principal)
            } else {
                runtime_bridge::guest_notes(principal)
            },
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
        if let Some(missing) = runtime_gap(step) {
            text.push_str("Runtime: BLOCKED\nMissing: ");
            text.push_str(missing);
            text.push('\n');
        }
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
                journal: false,
            },
            PlannedStep {
                action: Action::Write,
                operation: "write",
                journal: true,
            },
        ]),
        _ => Err(Refuse::UnknownIntent),
    }
}

#[cfg(test)]
const INTENT: &str = "summarize my notes into the journal";
#[cfg(test)]
const PREVIEW: &str = "\
Plan preview
Intent: summarize my notes into the journal
Principal: ada
This preview shows the steps. A grant is recorded only when you approve this plan.

Step 1
Capability: read
Operation: read
Resource: localhost://UsersAI/ada/notes
Runtime: BLOCKED
Missing: scope_current_user_alias does not bind a UsersAI principal root

Step 2
Capability: write
Operation: write
Resource: localhost://Users/self/.AppData/Agents/ada/tasks/task-1/journal
";

#[cfg(test)]
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
    assert_eq!(plan.steps[0].resource, runtime_bridge::guest_notes("ada"));
    assert_eq!(
        runtime_gap(&plan.steps[0]),
        Some(runtime_bridge::USERS_AI_GAP)
    );
    assert_eq!(plan.steps[1].id, 2);
    assert_eq!(plan.steps[1].capability.action, Action::Write);
    assert_eq!(plan.steps[1].capability.operation, "write");
    assert_eq!(plan.steps[1].resource, runtime_bridge::guest_journal("ada"));
    assert_eq!(runtime_gap(&plan.steps[1]), None);
    assert_eq!(crate::plan("ada", INTENT).expect("again"), plan);
    assert_eq!(preview(&plan), PREVIEW);

    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(preview(&plan), PREVIEW);
    assert_eq!(review.grants().len(), 1);
    for grant in review.grants() {
        assert!(!PREVIEW.contains(grant.token()));
    }
}

#[test]
fn approved_plan_records_blocked_in_process_bridge_effects() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.choice(), Choice::Approve);
    host.execute(&review, &plan, &plan.steps).expect("run");
    assert_eq!(host.effects().len(), plan.steps.len());
    assert_eq!(host.effects()[0].grant_token, "");
    assert_eq!(
        host.effects()[0].kind,
        EffectKind::Blocked {
            missing: runtime_bridge::USERS_AI_GAP.to_owned(),
            code: String::new(),
        }
    );
    let grant = &review.grants()[0];
    let journal = &host.effects()[1];
    assert_eq!(journal.step_id, grant.step_id());
    assert_eq!(journal.action, grant.action());
    assert_eq!(journal.operation, grant.operation());
    assert_eq!(journal.resource, grant.resource());
    assert_eq!(journal.grant_token, grant.token());
    assert_eq!(
        journal.kind,
        EffectKind::Blocked {
            missing: runtime_bridge::STORAGE_BRIDGE_GAP.to_owned(),
            code: runtime_bridge::STORAGE_BRIDGE_CODE.to_owned(),
        }
    );
    let token = elastos_runtime::capability::CapabilityToken::from_base64(grant.token())
        .expect("lab token");
    assert_eq!(token.capsule(), runtime_bridge::CAPSULE_ID);
    assert_eq!(
        token.action().to_string(),
        elastos_runtime::capability::Action::Write.to_string()
    );
    assert_eq!(token.constraints().max_uses(), Some(1));
    assert_eq!(
        token.resource().as_str(),
        runtime_bridge::scoped_journal("ada")
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
    altered.steps[1].resource = runtime_bridge::guest_journal("ada").replace("journal", "secrets");
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
        resource: "localhost://UsersAI/ada/Projects/build".to_owned(),
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
fn dependencies_are_the_runtime_crates() {
    let _guard = plant::source_lock();
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    assert!(manifest.contains("../../elastos/crates/elastos-runtime"));
    assert!(manifest.contains("../../elastos/crates/elastos-server"));
    assert!(!manifest.contains("openai"));
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read src/lib.rs");
    assert!(
        lib.starts_with("#![forbid(unsafe_code)]"),
        "src/lib.rs must begin with forbid(unsafe_code)"
    );
}

#[test]
fn in_process_bridge_denies_an_unapproved_journal_step() {
    let reply = runtime_bridge::invoke_journal("", &runtime_bridge::guest_journal("ada"), None)
        .expect("bridge");
    assert_eq!(reply.code, runtime_bridge::MISSING_TOKEN_CODE);
    assert_eq!(reply.message, runtime_bridge::MISSING_TOKEN_MESSAGE);
}

#[test]
fn lab_manager_denies_an_altered_journal_resource() {
    let grants = runtime_bridge::Grants::new();
    let token = grants.mint_journal_write("ada");
    let altered = runtime_bridge::scoped_journal("ada").replace("journal", "secrets");
    let error = grants
        .validate_journal_write(&token, &altered)
        .expect_err("altered resource");
    assert!(
        error.contains("wrong resource"),
        "CapabilityManager::validate: {error}"
    );
    grants
        .validate_journal_write(&token, &runtime_bridge::scoped_journal("ada"))
        .expect("the failed check does not spend the one use");
}

#[test]
fn lab_manager_denies_a_reused_single_use_grant() {
    let grants = runtime_bridge::Grants::new();
    let token = grants.mint_journal_write("ada");
    let resource = runtime_bridge::scoped_journal("ada");
    grants
        .validate_journal_write(&token, &resource)
        .expect("first use");
    let error = grants
        .validate_journal_write(&token, &resource)
        .expect_err("second use");
    assert!(
        error.contains("use limit exceeded"),
        "CapabilityManager::validate: {error}"
    );
}

#[test]
fn public_bridge_blocks_journal_storage_before_token_checks() {
    let grants = runtime_bridge::Grants::new();
    let token = grants.mint_journal_write("ada");
    let altered = runtime_bridge::guest_journal("ada").replace("journal", "secrets");
    let reply = runtime_bridge::invoke_journal(&token, &altered, None).expect("bridge");
    assert_eq!(reply.code, runtime_bridge::STORAGE_BRIDGE_CODE);
    assert_eq!(reply.message, runtime_bridge::STORAGE_BRIDGE_GAP);
    assert_ne!(reply.code, "capability_denied");
    let again = runtime_bridge::invoke_journal(&token, &runtime_bridge::guest_journal("ada"), None)
        .expect("bridge");
    assert_eq!(again.code, runtime_bridge::STORAGE_BRIDGE_CODE);
    assert_eq!(again.message, runtime_bridge::STORAGE_BRIDGE_GAP);
}

#[test]
fn reordered_approved_steps_are_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut steps = plan.steps.clone();
    steps.swap(0, 1);
    assert_eq!(steps.len(), plan.steps.len());
    let error = host.execute(&review, &plan, &steps).expect_err("reordered");
    assert_eq!(error, Refuse::OutsidePlan);
    assert_eq!(error.to_string(), "a step is outside the approved plan");
    assert!(host.effects().is_empty());
}

#[test]
fn grant_lookup_uses_covers_for_the_exact_resource() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada"), journal_write_step(2, "bea")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.grants().len(), 2);
    assert!(review.grants()[0].covers(&plan.steps[0]));
    assert!(!review.grants()[0].covers(&plan.steps[1]));
    assert!(review.grants()[1].covers(&plan.steps[1]));
    assert_ne!(review.grants()[0].token(), review.grants()[1].token());
    host.execute(&review, &plan, &plan.steps).expect("run");
    assert_eq!(host.effects().len(), 2);
    for (effect, grant) in host.effects().iter().zip(review.grants()) {
        assert_eq!(effect.grant_token, grant.token());
        assert_eq!(effect.resource, grant.resource());
        assert_eq!(effect.action, grant.action());
        assert_eq!(effect.operation, grant.operation());
        assert_eq!(effect.step_id, grant.step_id());
    }
}

#[test]
fn unused_review_does_not_run_on_a_second_host() {
    let plan = sample();
    let mut host_a = Host::new();
    let review = host_a.review(&plan, Choice::Approve);
    let mut host_b = Host::new();
    let error = host_b
        .execute(&review, &plan, &plan.steps)
        .expect_err("foreign host");
    assert_eq!(error, Refuse::ForeignHost);
    assert_eq!(error.to_string(), "the review was minted by another host");
    assert!(host_a.effects().is_empty());
    assert!(host_b.effects().is_empty());
}

#[test]
fn execute_spends_the_allow_once_grant_at_the_lab_manager() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let token = review.grants()[0].token().to_owned();
    let resource = runtime_bridge::scoped_journal("ada");
    host.execute(&review, &plan, &plan.steps).expect("run");
    let spent = host
        .validate_journal_write(&token, &resource)
        .expect_err("execute must call validate_journal_write");
    assert!(
        spent.contains("use limit exceeded"),
        "lab CapabilityManager after execute: {spent}"
    );
}

#[test]
fn blocked_journal_effect_comes_from_a_bus_round_trip() {
    let plan = sample();
    let mut host = Host::new();
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());
    let review = host.review(&plan, Choice::Approve);
    host.execute(&review, &plan, &plan.steps).expect("run");
    let journal = &host.effects()[1];
    assert_eq!(
        journal.kind,
        EffectKind::Blocked {
            missing: runtime_bridge::STORAGE_BRIDGE_GAP.to_owned(),
            code: runtime_bridge::STORAGE_BRIDGE_CODE.to_owned(),
        }
    );
    let audit = runtime_bridge::component_invoke_audit(host.audit_dir());
    assert_eq!(audit.len(), 2, "in-process bus audit: {audit:?}");
    assert_eq!(audit[0].0, "component.invoke.requested");
    assert_eq!(audit[0].1, "pending");
    assert!(
        audit[0].2.contains("write") && audit[0].2.contains("journal"),
        "requested reason: {}",
        audit[0].2
    );
    assert_eq!(audit[1].0, "component.invoke.completed");
    assert_eq!(audit[1].1, "denied");
    assert_eq!(audit[0].2, audit[1].2);
}

#[test]
fn approval_for_one_principal_does_not_execute_for_another() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut other = plan.clone();
    other.principal = "bea".to_owned();
    assert_eq!(other.steps, plan.steps);
    assert_ne!(plan.canonical(), other.canonical());
    let error = host
        .execute(&review, &other, &other.steps)
        .expect_err("other principal");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[cfg(test)]
fn journal_write_step(id: u32, agent: &str) -> Step {
    Step {
        id,
        capability: Capability {
            action: Action::Write,
            operation: "write".to_owned(),
        },
        resource: runtime_bridge::guest_journal(agent),
    }
}

#[test]
fn model_planted_bugs_are_caught() {
    let _guard = plant::source_lock();
    plant::run_all();
}
