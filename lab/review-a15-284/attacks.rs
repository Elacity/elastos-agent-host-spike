//! Adversarial probes run against #284 at cb102ed1.
//! Record only. This file is not part of the intent-planner crate.

use super::*;
use crate::runtime_bridge::{
    guest_journal, invoke_journal, scoped_journal, Grants, STORAGE_BRIDGE_CODE, STORAGE_BRIDGE_GAP,
};

fn sample() -> Plan {
    plan("ada", INTENT).expect("plan")
}

#[test]
fn reorder_steps_after_approval_is_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut steps = plan.steps.clone();
    steps.swap(0, 1);
    let error = host
        .execute(&review, &plan, &steps)
        .expect_err("reordered");
    assert_eq!(error, Refuse::OutsidePlan);
    assert_eq!(error.to_string(), "a step is outside the approved plan");
    assert!(host.effects().is_empty());
}

#[test]
fn edited_operation_after_approval_is_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut steps = plan.steps.clone();
    steps[1].capability.operation = "append".to_owned();
    let error = host
        .execute(&review, &plan, &steps)
        .expect_err("edited operation");
    assert_eq!(error, Refuse::OutsidePlan);
    assert!(host.effects().is_empty());
}

#[test]
fn edited_action_after_approval_is_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let mut steps = plan.steps.clone();
    steps[1].capability.action = Action::Read;
    let error = host
        .execute(&review, &plan, &steps)
        .expect_err("edited action");
    assert_eq!(error, Refuse::OutsidePlan);
    assert!(host.effects().is_empty());
}

#[test]
fn other_principal_plan_is_refused() {
    let ada = sample();
    let bea = plan("bea", INTENT).expect("bea");
    let mut host = Host::new();
    let review = host.review(&ada, Choice::Approve);
    let error = host
        .execute(&review, &bea, &bea.steps)
        .expect_err("other principal");
    assert_eq!(error, Refuse::PlanAltered);
    assert_eq!(error.to_string(), "the plan was altered after approval");
    assert!(host.effects().is_empty());
}

#[test]
fn review_replayed_on_another_host() {
    let plan = sample();
    let mut first = Host::new();
    let review = first.review(&plan, Choice::Approve);
    first.execute(&review, &plan, &plan.steps).expect("first");
    let first_effects = first.effects().len();
    let mut second = Host::new();
    let error = second
        .execute(&review, &plan, &plan.steps)
        .expect_err("replay on other host");
    assert_eq!(error, Refuse::Bridge);
    assert_eq!(error.to_string(), "the bus bridge did not answer");
    // approval_check passes on the second Host. Step 1 is recorded, then
    // validate fails for a token minted by another manager. Effects are not
    // rolled back.
    assert_eq!(first_effects, 2);
    assert_eq!(second.effects().len(), 1);
    assert_eq!(second.effects()[0].step_id, 1);
    assert_eq!(
        second.effects()[0].kind,
        EffectKind::Blocked {
            missing: crate::runtime_bridge::USERS_AI_GAP.to_owned(),
            code: String::new(),
        }
    );
}

#[test]
fn unused_review_on_another_host() {
    let plan = sample();
    let mut first = Host::new();
    let review = first.review(&plan, Choice::Approve);
    let mut second = Host::new();
    let error = second
        .execute(&review, &plan, &plan.steps)
        .expect_err("other host, unused");
    assert_eq!(error, Refuse::Bridge);
    assert_eq!(second.effects().len(), 1);
    assert_eq!(second.effects()[0].step_id, 1);
}

#[test]
fn empty_constructed_plan_executes_nothing() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: INTENT.to_owned(),
        steps: Vec::new(),
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert!(review.grants().is_empty());
    host.execute(&review, &plan, &[]).expect("empty approved");
    assert!(host.effects().is_empty());
}

#[test]
fn partial_steps_are_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let error = host
        .execute(&review, &plan, &plan.steps[1..])
        .expect_err("partial");
    assert_eq!(error, Refuse::OutsidePlan);
    assert!(host.effects().is_empty());
}

#[test]
fn forged_token_on_public_bridge_is_storage_blocked() {
    let reply = invoke_journal("forged-not-a-runtime-token", &guest_journal("ada"))
        .expect("bridge accepts the call");
    assert_eq!(reply.code, STORAGE_BRIDGE_CODE);
    assert_eq!(reply.message, STORAGE_BRIDGE_GAP);
}

#[test]
fn stolen_token_reaches_bridge_without_host_execute() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let token = review.grants()[0].token().to_owned();
    let reply = invoke_journal(&token, &guest_journal("ada")).expect("direct");
    assert_eq!(reply.code, STORAGE_BRIDGE_CODE);
    assert!(host.effects().is_empty());
}

#[test]
fn minted_token_bypasses_preview_and_approval() {
    let grants = Grants::new();
    let token = grants.mint_journal_write("ada");
    let reply = invoke_journal(&token, &guest_journal("ada")).expect("mint+invoke");
    assert_eq!(reply.code, STORAGE_BRIDGE_CODE);
}

#[test]
fn preview_records_no_grant_and_does_not_execute() {
    let plan = sample();
    let text = preview(&plan);
    assert!(text.contains("A grant is recorded only when you approve this plan."));
    let host = Host::new();
    assert!(host.effects().is_empty());
}

#[test]
fn no_elastos_runtime_process_during_bridge_call() {
    fn elastos_comms() -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(dir) = std::fs::read_dir("/proc") {
            for entry in dir.flatten() {
                let pid = entry.file_name();
                let pid = match pid.to_str().and_then(|s| s.parse::<i32>().ok()) {
                    Some(pid) => pid,
                    None => continue,
                };
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                if comm.contains("elastos") {
                    names.push(format!("{}:{}", pid, comm.trim()));
                }
            }
        }
        names
    }
    let before = elastos_comms();
    let _ = invoke_journal("", &guest_journal("ada"));
    let after = elastos_comms();
    assert_eq!(
        before, after,
        "invoke_journal must not start an elastos process; before={before:?} after={after:?}"
    );
}

#[test]
fn scoped_journal_uses_lab_person_not_agent_principal() {
    let ada = scoped_journal("ada");
    let bea = scoped_journal("bea");
    assert!(ada.contains("/.AppData/Agents/ada/"));
    assert!(bea.contains("/.AppData/Agents/bea/"));
    assert_ne!(ada, bea);
}

#[test]
fn constructed_step_can_be_approved_without_planner() {
    let plan = Plan {
        principal: "ada".to_owned(),
        intent: "not in the table".to_owned(),
        steps: vec![Step {
            id: 1,
            capability: Capability {
                action: Action::Write,
                operation: "write".to_owned(),
            },
            resource: guest_journal("ada"),
        }],
    };
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(review.grants().len(), 1);
    host.execute(&review, &plan, &plan.steps)
        .expect("constructed plan runs");
    assert_eq!(host.effects().len(), 1);
}
