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
//! A rejected plan, a plan whose bytes changed after approval, a constructed
//! plan whose length-prefixed bytes collide only if the prefix is dropped, a
//! run list that is not the approved ordered list, a review from another Host
//! (`host-1` is not `host-10`), an empty, NUL, `.`, `..`, `a..b`, or `...`
//! `host_id`, and a second use of the same grant all stop before a grant is
//! spent. The same strict ASCII name grammar `plan()` applies is applied at
//! `execute()` to every name field (principal, including the `plain_principal`
//! start and end rules, intent, path segments, and `host_id`). A constructed
//! `_ada`, `ada.`, or `.ada` principal, a NUL in the intent, and those
//! `host_id` values are refused with a named error. An empty or zero-step plan
//! cannot be approved. Duplicate steps in one plan are refused at approval, so
//! the result is never two grants or two bus calls. Names and paths are
//! checked against that grammar before any compare or hash and refused, never
//! folded or truncated. `canonical()` keeps the plan step order. A failed
//! execute does not spend. A step the Runtime cannot express is BLOCKED with
//! the missing capability. The public entry does not store a journal. A
//! `stored` bus reply, or any reply other than the exact BLOCKED token, fails
//! the run.

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
    /// later edit cannot keep the same binding by moving a separator. Steps
    /// stay in plan order: approving `[notes, journal]` never binds
    /// `[journal, notes]`. Fields are the bytes as given. Nothing is folded,
    /// case-mapped, or truncated.
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
    BadIntent,
    EmptyPlan,
    DuplicateStep,
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
            Refuse::BadIntent => "intent is not a single plain field",
            Refuse::EmptyPlan => "the plan has no steps",
            Refuse::DuplicateStep => "the plan lists a step more than once",
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
            && exact_resource(&self.resource, &step.resource)
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
    /// An empty or duplicate-step plan cannot be approved: the recorded choice
    /// is Reject and no grant is minted.
    pub fn review(&mut self, plan: &Plan, choice: Choice) -> Review {
        let choice = match plan_steps_admissible(&plan.steps) {
            Ok(()) => choice,
            Err(_) => Choice::Reject,
        };
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
        plan_steps_admissible(&plan.steps)?;
        plan_steps_admissible(steps)?;
        let allowed = self.approval_check(review, plan, steps)?;
        if !plain_principal(&plan.principal) {
            return Err(Refuse::BadPrincipal);
        }
        if !plain_intent(&plan.intent) {
            return Err(Refuse::BadIntent);
        }
        if steps
            .iter()
            .any(|step| validated_path(&step.resource).is_none())
        {
            return Err(Refuse::OutsidePlan);
        }
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
                    return Err(Refuse::Bridge);
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
            spent.push(grant.clone());
        }
        for grant in &spent {
            let agent = plan_agent(&grant.resource);
            self.grants
                .validate_journal_write(&grant.token, &runtime_bridge::scoped_journal(agent))
                .map_err(|_| Refuse::Bridge)?;
        }
        self.effects.extend(recorded);
        self.used
            .extend(spent.iter().map(|grant| grant.token.clone()));
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
        if validated_name(&review.host_id).is_none() {
            return Err(Refuse::ForeignHost);
        }
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

const NAME_MAX: usize = 64;
const RESOURCE_MAX: usize = 255;

/// A name is one grammar segment: ASCII `[a-z0-9._-]`, no empty value, no
/// `.` or `..`, no embedded `..` (`a..b`, `...`), no `%`, no NUL, no
/// uppercase. Over-length is refused.
fn validated_name(raw: &str) -> Option<&str> {
    if raw.is_empty()
        || raw.len() > NAME_MAX
        || raw.contains('\0')
        || raw.contains('%')
        || raw.contains("..")
        || raw == "."
        || raw == ".."
    {
        return None;
    }
    if raw.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        Some(raw)
    } else {
        None
    }
}

/// A resource path is refused (not normalised) when it fails the grammar.
/// The Runtime guest URI keeps its existing `localhost://Users/...` alphabet
/// (ASCII letters in either case). Segments are `[A-Za-z0-9._-]`, `/`
/// separated, with no empty, `.`, or `..` segment, no embedded `..`
/// (`a..b`, `...`), no trailing slash, no `%`, no NUL. Over-length is
/// refused. The value returned is the original bytes. Nothing is folded,
/// decoded, or truncated.
fn validated_path(raw: &str) -> Option<&str> {
    if raw.is_empty()
        || raw.len() > RESOURCE_MAX
        || !raw.is_ascii()
        || raw.contains('\0')
        || raw.contains('%')
        || raw.ends_with('/')
    {
        return None;
    }
    let path = raw.strip_prefix("localhost://").unwrap_or(raw);
    if path.is_empty() {
        return None;
    }
    if path.split('/').all(valid_path_segment) {
        Some(raw)
    } else {
        None
    }
}

fn valid_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains("..")
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn exact_resource(granted: &str, requested: &str) -> bool {
    match (validated_path(granted), validated_path(requested)) {
        (Some(granted), Some(requested)) => granted.split('/').eq(requested.split('/')),
        _ => false,
    }
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
    if !plain_intent(intent) {
        return Err(Refuse::BadIntent);
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
    plan_steps_admissible(&steps)?;
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
/// and it does not end in `.`. `_ada`, `ada.`, `.ada`, `a..b`, and `...`
/// are refused.
fn plain_principal(name: &str) -> bool {
    validated_name(name).is_some()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !name.ends_with('.')
}

/// Intent bytes are refused, never folded. A NUL is a named refusal.
fn plain_intent(intent: &str) -> bool {
    !intent.contains('\0')
}

/// An empty step list, or a repeated `step.id` or resource, cannot be
/// approved and cannot execute.
fn plan_steps_admissible(steps: &[Step]) -> Result<(), Refuse> {
    if steps.is_empty() {
        return Err(Refuse::EmptyPlan);
    }
    if has_duplicate_steps(steps) {
        return Err(Refuse::DuplicateStep);
    }
    Ok(())
}

fn has_duplicate_steps(steps: &[Step]) -> bool {
    steps.iter().enumerate().any(|(index, step)| {
        steps[..index]
            .iter()
            .any(|prior| prior.id == step.id || prior.resource == step.resource)
    })
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
    assert_eq!(plan("_ada", INTENT).unwrap_err(), Refuse::BadPrincipal);
    assert_eq!(plan(".ada", INTENT).unwrap_err(), Refuse::BadPrincipal);
    assert_eq!(plan("a..b", INTENT).unwrap_err(), Refuse::BadPrincipal);
    assert_eq!(plan("...", INTENT).unwrap_err(), Refuse::BadPrincipal);
    assert_eq!(
        plan("ada", &format!("{INTENT}\0extra")).unwrap_err(),
        Refuse::BadIntent
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
fn blocked_journal_effect_comes_from_an_in_process_library_call() {
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

#[test]
fn newline_fields_do_not_collide() {
    let left_run = Plan {
        principal: "a\nb".to_owned(),
        intent: "c".to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    let right_run = Plan {
        principal: "a".to_owned(),
        intent: "b\nc".to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    assert_ne!(left_run.canonical(), right_run.canonical());
    let mut host = Host::new();
    let review = host.review(&left_run, Choice::Approve);
    let error = host
        .execute(&review, &right_run, &right_run.steps)
        .expect_err("newline field split");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn trailing_space_principal_is_a_different_plan() {
    let plan = sample();
    let mut spaced = plan.clone();
    spaced.principal = "ada ".to_owned();
    assert_ne!(plan.canonical(), spaced.canonical());
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let error = host
        .execute(&review, &spaced, &spaced.steps)
        .expect_err("trailing space");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn prefix_resource_does_not_cover_a_child_journal() {
    let parent = Step {
        id: 1,
        capability: Capability {
            action: Action::Write,
            operation: "write".to_owned(),
        },
        resource: "localhost://Users/self/.AppData/Agents/ada/tasks".to_owned(),
    };
    let child = Step {
        id: 1,
        capability: Capability {
            action: Action::Write,
            operation: "write".to_owned(),
        },
        resource: runtime_bridge::guest_journal("ada"),
    };
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![parent, child],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.grants().len(), 2);
    assert!(
        !review.grants()[0].covers(&plan.steps[1]),
        "a parent-path grant must not cover the child journal"
    );
    assert!(review.grants()[0].covers(&plan.steps[0]));
    assert!(review.grants()[1].covers(&plan.steps[1]));
}

#[test]
fn approved_plan_refuses_a_stored_bus_reply() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    runtime_bridge::force_next_journal_reply(runtime_bridge::BridgeReply {
        code: "stored".to_owned(),
        message: "probe-stored-journal".to_owned(),
    });
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("stored reply");
    assert_eq!(error, Refuse::Bridge);
    assert_eq!(error.to_string(), "the bus bridge did not answer");
    assert!(host.effects().is_empty());
    host.execute(&review, &plan, &plan.steps)
        .expect("retry after a stored reply must still run");
    assert_eq!(host.effects().len(), plan.steps.len());
}

#[test]
fn prefix_host_id_stays_foreign() {
    let plan = sample();
    let mut first = Host::new();
    first.id = "host-1".to_owned();
    let review = first.review(&plan, Choice::Approve);
    let mut other = Host::new();
    other.id = "host-10".to_owned();
    let error = other
        .execute(&review, &plan, &plan.steps)
        .expect_err("prefix host id");
    assert_eq!(error, Refuse::ForeignHost);
    assert_eq!(error.to_string(), "the review was minted by another host");
    assert!(first.effects().is_empty());
    assert!(other.effects().is_empty());
}

#[test]
fn failed_execute_does_not_spend_the_grant() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let token = review.grants()[0].token().to_owned();
    let resource = runtime_bridge::scoped_journal("ada");
    runtime_bridge::force_next_journal_fail();
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("forced bus fail");
    assert_eq!(error, Refuse::Bridge);
    assert!(host.effects().is_empty());
    host.execute(&review, &plan, &plan.steps)
        .expect("retry after a failed execute");
    assert_eq!(host.effects().len(), plan.steps.len());
    let spent = host
        .validate_journal_write(&token, &resource)
        .expect_err("grant is spent only after confirmed success");
    assert!(
        spent.contains("use limit exceeded"),
        "lab CapabilityManager after successful retry: {spent}"
    );

    let mut replay = Host::new();
    let review = replay.review(&plan, Choice::Approve);
    let token = review.grants()[0].token().to_owned();
    replay
        .validate_journal_write(&token, &resource)
        .expect("spend before execute");
    let error = replay
        .execute(&review, &plan, &plan.steps)
        .expect_err("spent between approve and execute");
    assert_eq!(error, Refuse::Bridge);
    assert!(replay.effects().is_empty());
    let again = replay
        .execute(&review, &plan, &plan.steps)
        .expect_err("retry after failed execute");
    assert_eq!(again, Refuse::Bridge);
    assert_ne!(again, Refuse::GrantSpent);
}

#[test]
fn nfc_nfd_principals_do_not_collide() {
    let mut nfc = sample();
    nfc.principal = "caf\u{e9}".to_owned();
    let mut nfd = nfc.clone();
    nfd.principal = "cafe\u{301}".to_owned();
    assert_ne!(nfc.canonical(), nfd.canonical());
    let mut host = Host::new();
    let review = host.review(&nfc, Choice::Approve);
    let error = host
        .execute(&review, &nfd, &nfd.steps)
        .expect_err("nfc/nfd");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn cyrillic_confusable_principal_is_a_different_plan() {
    let mut latin = sample();
    latin.principal = "ada".to_owned();
    let mut cyrillic = latin.clone();
    cyrillic.principal = "\u{430}da".to_owned();
    assert_ne!(latin.canonical(), cyrillic.canonical());
    let mut host = Host::new();
    let review = host.review(&latin, Choice::Approve);
    let error = host
        .execute(&review, &cyrillic, &cyrillic.steps)
        .expect_err("confusable");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn over_length_field_is_not_truncated() {
    let head = "a".repeat(255);
    let mut left = sample();
    left.principal = format!("{head}b");
    let mut right = sample();
    right.principal = format!("{head}c");
    assert!(left.canonical().starts_with("256:"));
    assert!(right.canonical().starts_with("256:"));
    assert_ne!(left.canonical(), right.canonical());
    let mut host = Host::new();
    let review = host.review(&left, Choice::Approve);
    let error = host
        .execute(&review, &right, &right.steps)
        .expect_err("over-length");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
    let same = host
        .execute(&review, &left, &left.steps)
        .expect_err("over-length same plan");
    assert_eq!(same, Refuse::BadPrincipal);
    assert!(host.effects().is_empty());
}

#[test]
fn dotdot_path_does_not_cover_journal() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut walk = plan.steps[0].clone();
    walk.resource.push_str("/foo/..");
    assert!(
        !review.grants()[0].covers(&walk),
        "a .. segment must not cover the journal"
    );
    assert!(review.grants()[0].covers(&plan.steps[0]));
}

#[test]
fn trailing_slash_path_does_not_cover_journal() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut slashed = plan.steps[0].clone();
    slashed.resource.push('/');
    assert!(
        !review.grants()[0].covers(&slashed),
        "a trailing slash must not cover the journal"
    );
    assert!(review.grants()[0].covers(&plan.steps[0]));
}

#[test]
fn ascii_case_path_does_not_cover_journal() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut folded = plan.steps[0].clone();
    folded.resource = folded.resource.replacen("/ada/", "/Ada/", 1);
    assert_ne!(folded.resource, plan.steps[0].resource);
    assert!(
        !review.grants()[0].covers(&folded),
        "ASCII case must not cover the journal"
    );
    assert!(review.grants()[0].covers(&plan.steps[0]));
}

#[test]
fn blocked_reply_is_a_whole_token() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    runtime_bridge::force_next_journal_reply(runtime_bridge::BridgeReply {
        code: format!("{} ", runtime_bridge::STORAGE_BRIDGE_CODE),
        message: format!("{} trailing", runtime_bridge::STORAGE_BRIDGE_GAP),
    });
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("trimmed blocked reply");
    assert_eq!(error, Refuse::Bridge);
    assert_eq!(error.to_string(), "the bus bridge did not answer");
    assert!(host.effects().is_empty());

    runtime_bridge::force_next_journal_reply(runtime_bridge::BridgeReply {
        code: runtime_bridge::STORAGE_BRIDGE_CODE.to_ascii_uppercase(),
        message: runtime_bridge::STORAGE_BRIDGE_GAP.to_owned(),
    });
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("case-folded blocked reply");
    assert_eq!(error, Refuse::Bridge);
    assert!(host.effects().is_empty());

    runtime_bridge::force_next_journal_reply(runtime_bridge::BridgeReply {
        code: runtime_bridge::STORAGE_BRIDGE_CODE.to_owned(),
        message: format!("{} extra", runtime_bridge::STORAGE_BRIDGE_GAP),
    });
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("prefix blocked reply");
    assert_eq!(error, Refuse::Bridge);
    assert!(host.effects().is_empty());

    host.execute(&review, &plan, &plan.steps)
        .expect("exact blocked token still runs");
    assert_eq!(host.effects().len(), plan.steps.len());
}

#[test]
fn empty_or_nul_host_id_is_foreign() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);

    let mut empty = review.clone();
    empty.host_id.clear();
    let error = host
        .execute(&empty, &plan, &plan.steps)
        .expect_err("empty host id");
    assert_eq!(error, Refuse::ForeignHost);
    assert_eq!(error.to_string(), "the review was minted by another host");
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());

    let mut nulled = review.clone();
    nulled.host_id = format!("{}\0", host.id);
    let error = host
        .execute(&nulled, &plan, &plan.steps)
        .expect_err("nul host id");
    assert_eq!(error, Refuse::ForeignHost);
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());

    let mut other = Host::new();
    other.id = "host-99".to_owned();
    let mut blank = review.clone();
    blank.host_id.clear();
    let error = other
        .execute(&blank, &plan, &plan.steps)
        .expect_err("empty vs host-99");
    assert_eq!(error, Refuse::ForeignHost);
    assert!(other.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(other.audit_dir()).is_empty());
}

#[test]
fn approved_step_order_is_bound() {
    let plan = sample();
    assert_eq!(plan.steps[0].resource, runtime_bridge::guest_notes("ada"));
    assert_eq!(plan.steps[1].resource, runtime_bridge::guest_journal("ada"));
    let mut swapped = plan.clone();
    swapped.steps.swap(0, 1);
    assert_ne!(plan.canonical(), swapped.canonical());
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let error = host
        .execute(&review, &swapped, &swapped.steps)
        .expect_err("swapped plan object");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn percent_encoded_path_does_not_cover_journal() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut encoded = plan.steps[0].clone();
    encoded.resource = encoded.resource.replacen("journal", "journa%6c", 1);
    assert!(
        !review.grants()[0].covers(&encoded),
        "percent-encoding must not cover the journal"
    );
    assert!(review.grants()[0].covers(&plan.steps[0]));
}

#[test]
fn constructed_plain_principal_is_refused_at_execute() {
    for name in ["_ada", "ada.", ".ada"] {
        let mut plan = sample();
        plan.principal = name.to_owned();
        let mut host = Host::new();
        let review = host.review(&plan, Choice::Approve);
        assert_eq!(review.choice(), Choice::Approve);
        assert_eq!(review.grants().len(), 1);
        let error = host.execute(&review, &plan, &plan.steps).expect_err(name);
        assert_eq!(error, Refuse::BadPrincipal, "{name}");
        assert_eq!(error.to_string(), "principal is not a single plain name");
        assert!(host.effects().is_empty(), "{name}");
        assert!(
            runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty(),
            "{name}"
        );
    }
}

#[test]
fn nul_intent_is_refused_at_execute() {
    let mut plan = sample();
    plan.intent = format!("{INTENT}\0extra");
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.choice(), Choice::Approve);
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("nul intent");
    assert_eq!(error, Refuse::BadIntent);
    assert_eq!(error.to_string(), "intent is not a single plain field");
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());
}

#[test]
fn empty_plan_cannot_be_approved() {
    let empty = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: Vec::new(),
    };
    let mut host = Host::new();
    let review = host.review(&empty, Choice::Approve);
    assert_eq!(review.choice(), Choice::Reject);
    assert!(review.grants().is_empty());
    let error = host
        .execute(&review, &empty, &empty.steps)
        .expect_err("empty plan");
    assert_eq!(error, Refuse::EmptyPlan);
    assert_eq!(error.to_string(), "the plan has no steps");
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());
}

#[test]
fn duplicate_journal_steps_are_refused() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: vec![journal_write_step(1, "ada"), journal_write_step(2, "ada")],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.choice(), Choice::Reject);
    assert!(
        review.grants().is_empty(),
        "duplicate journal steps must not mint two grants"
    );
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("duplicate steps");
    assert_eq!(error, Refuse::DuplicateStep);
    assert_eq!(error.to_string(), "the plan lists a step more than once");
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());
}

#[test]
fn dot_or_dotdot_host_id_is_foreign() {
    let plan = sample();
    for id in [".", ".."] {
        let mut host = Host::new();
        host.id = id.to_owned();
        let review = host.review(&plan, Choice::Approve);
        assert_eq!(review.host_id, id);
        let error = host.execute(&review, &plan, &plan.steps).expect_err(id);
        assert_eq!(error, Refuse::ForeignHost, "{id}");
        assert_eq!(error.to_string(), "the review was minted by another host");
        assert!(host.effects().is_empty(), "{id}");
        assert!(
            runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty(),
            "{id}"
        );
    }
}

#[test]
fn embedded_dotdot_host_id_is_foreign() {
    let plan = sample();
    for id in ["a..b", "..."] {
        let mut host = Host::new();
        host.id = id.to_owned();
        let review = host.review(&plan, Choice::Approve);
        assert_eq!(review.host_id, id);
        let error = host.execute(&review, &plan, &plan.steps).expect_err(id);
        assert_eq!(error, Refuse::ForeignHost, "{id}");
        assert!(host.effects().is_empty(), "{id}");
        assert!(
            runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty(),
            "{id}"
        );
    }
}

#[test]
fn dotdot_notes_path_is_refused_at_execute() {
    let mut walk = sample();
    walk.steps[0].resource.push_str("/foo/..");
    let mut host = Host::new();
    let review = host.review(&walk, Choice::Approve);
    assert_eq!(review.grants().len(), 1);
    let error = host
        .execute(&review, &walk, &walk.steps)
        .expect_err("notes/foo/..");
    assert_eq!(error, Refuse::OutsidePlan);
    assert_eq!(error.to_string(), "a step is outside the approved plan");
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());

    let mut embedded = sample();
    embedded.steps[0].resource.push_str("/a..b");
    let review = host.review(&embedded, Choice::Approve);
    let error = host
        .execute(&review, &embedded, &embedded.steps)
        .expect_err("notes/a..b");
    assert_eq!(error, Refuse::OutsidePlan);
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
