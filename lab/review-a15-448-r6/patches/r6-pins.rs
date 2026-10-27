// Append to lab/intent-planner/src/lib.rs under #[cfg(test)].
// Each test must keep component_invoke_audit empty.

#[test]
fn forged_foreign_token_does_not_reach_the_bus() {
    let plan = sample();
    let mut host = Host::new();
    let mut review = host.review(&plan, Choice::Approve);
    review.grants[0].token = runtime_bridge::Grants::new().mint_journal_write("ada");
    let error = host
        .execute(&review, &plan, &plan.steps)
        .expect_err("foreign token");
    assert_ne!(error, Refuse::GrantSpent);
    assert!(host.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host.audit_dir()).is_empty());
}

#[test]
fn rewritten_grant_and_review_host_id_does_not_reach_the_bus() {
    let plan = sample();
    let mut host_a = Host::new();
    let review = host_a.review(&plan, Choice::Approve);
    let mut host_b = Host::new();
    let mut transplanted = review.clone();
    transplanted.host_id = host_b.id.clone();
    transplanted.grants[0].host_id = host_b.id.clone();
    let error = host_b
        .execute(&transplanted, &plan, &plan.steps)
        .expect_err("rewritten pair");
    assert_ne!(error, Refuse::GrantSpent);
    assert!(host_a.effects().is_empty());
    assert!(host_b.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host_a.audit_dir()).is_empty());
    assert!(runtime_bridge::component_invoke_audit(host_b.audit_dir()).is_empty());
}

#[test]
fn invalid_grant_host_id_does_not_skip_the_bind() {
    let plan = sample();
    let mut host_a = Host::new();
    let review = host_a.review(&plan, Choice::Approve);
    let mut host_b = Host::new();
    let mut transplanted = review.clone();
    transplanted.host_id = host_b.id.clone();
    transplanted.grants[0].host_id.clear();
    let error = host_b
        .execute(&transplanted, &plan, &plan.steps)
        .expect_err("empty grant host_id");
    assert_eq!(error, Refuse::ForeignHost);
    assert!(runtime_bridge::component_invoke_audit(host_a.audit_dir()).is_empty());
    assert!(runtime_bridge::component_invoke_audit(host_b.audit_dir()).is_empty());
}

#[test]
fn copied_host_id_does_not_run_on_a_second_host() {
    let plan = sample();
    let mut host_a = Host::new();
    let review = host_a.review(&plan, Choice::Approve);
    let mut host_b = Host::new();
    host_b.id = host_a.id.clone();
    host_b
        .execute(&review, &plan, &plan.steps)
        .expect_err("copied host id");
    assert!(host_a.effects().is_empty());
    assert!(host_b.effects().is_empty());
    assert!(runtime_bridge::component_invoke_audit(host_a.audit_dir()).is_empty());
    assert!(runtime_bridge::component_invoke_audit(host_b.audit_dir()).is_empty());
}
