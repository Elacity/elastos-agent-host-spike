//! Reviewer probes run against #284 at 4f17e482.
//! Record only. This file is not part of the intent-planner crate.
//!
//! The bodies were compiled in the detached worktree by appending them under
//! `#[cfg(test)]` in `src/lib.rs`, then removed. The candidate branch was
//! never pushed.

use super::*;
use crate::runtime_bridge;

#[test]
fn review_n1_newline_fields_do_not_collide() {
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
    let mut host = Host::new();
    let review = host.review(&left_run, Choice::Approve);
    if left_run.canonical() == right_run.canonical() {
        host.execute(&review, &right_run, &right_run.steps)
            .expect("N1 live: colliding P' executed");
        panic!("N1 live: execute returned Ok for a different plan");
    }
    let error = host
        .execute(&review, &right_run, &right_run.steps)
        .expect_err("colliding constructed plan");
    assert_eq!(error, Refuse::PlanAltered);
    assert!(host.effects().is_empty());
}

#[test]
fn review_n3_trailing_space_principal_is_a_different_plan() {
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
    assert!(host.effects().is_empty());
}

#[test]
fn review_n4_prefix_resource_does_not_cover() {
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
        resource: "localhost://Users/self/.AppData/Agents/ada/tasks/task-1/journal".to_owned(),
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
}

#[test]
fn review_n7_prefix_host_id_stays_foreign() {
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
    assert!(first.effects().is_empty());
    assert!(other.effects().is_empty());
}

#[test]
fn review_toctou_spend_before_execute_is_refused() {
    let plan = sample();
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    let token = review.grants()[0].token().to_owned();
    host.validate_journal_write(&token, &runtime_bridge::scoped_journal("ada"))
        .expect("spend before execute");
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("spent between approve and execute");
    assert!(host.effects().is_empty());
    assert_eq!(error, Refuse::Bridge);
    let again = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("retry after failed execute");
    assert_eq!(again, Refuse::Bridge);
}

#[test]
fn review_restart_drops_the_review() {
    let plan = sample();
    let review = {
        let mut host = Host::new();
        host.review(&plan, Choice::Approve)
    };
    let mut restarted = Host::new();
    let error = restarted
        .execute(&review, &plan, &plan.steps)
        .expect_err("host restart");
    assert_eq!(error, Refuse::ForeignHost);
    assert!(restarted.effects().is_empty());
}

#[test]
fn review_concurrent_validate_of_allow_once() {
    use std::sync::Arc;
    let grants = Arc::new(runtime_bridge::Grants::new());
    let token = grants.mint_journal_write("ada");
    let resource = runtime_bridge::scoped_journal("ada");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let grants = Arc::clone(&grants);
            let token = token.clone();
            let resource = resource.clone();
            let tx = tx.clone();
            scope.spawn(move || {
                tx.send(grants.validate_journal_write(&token, &resource))
                    .expect("send");
            });
        }
    });
    drop(tx);
    let results: Vec<_> = rx.iter().collect();
    assert_eq!(results.len(), 2);
    let oks = results.iter().filter(|r| r.is_ok()).count();
    let errs = results.iter().filter(|r| r.is_err()).count();
    assert_eq!(oks, 1, "allow-once must succeed once: {results:?}");
    assert_eq!(errs, 1, "allow-once must fail once: {results:?}");
}

#[test]
fn review_p_then_p_prime_same_canonical_is_refused() {
    let plan = sample();
    let mut reordered = plan.clone();
    reordered.steps.swap(0, 1);
    let mut spaced = plan.clone();
    spaced.intent = format!("{} ", plan.intent);
    assert_ne!(plan.canonical(), reordered.canonical());
    assert_ne!(plan.canonical(), spaced.canonical());
    let mut host = Host::new();
    let review = host.review(&plan, Choice::Approve);
    assert_eq!(
        host.execute(&review, &reordered, &reordered.steps)
            .expect_err("reordered plan object"),
        Refuse::PlanAltered
    );
    assert_eq!(
        host.execute(&review, &spaced, &spaced.steps)
            .expect_err("whitespace intent"),
        Refuse::PlanAltered
    );
    assert!(host.effects().is_empty());
}
