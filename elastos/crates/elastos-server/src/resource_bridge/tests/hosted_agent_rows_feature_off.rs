#![cfg(not(feature = "prototype-agents"))]
//! The hosted agent rows are compiled only in the agents build. This module
//! is that build's absence: cargo lists the ignored row and gives the reason.

#[test]
#[ignore = "agents are not built into this Runtime, so the hosted rows are not compiled"]
fn hosted_agent_rows_are_not_compiled() {
    let reason =
        crate::agents::require_build().expect_err("this build does not include the hosted rows");
    eprintln!("hosted_agent_rows is not compiled: {reason}");
}
