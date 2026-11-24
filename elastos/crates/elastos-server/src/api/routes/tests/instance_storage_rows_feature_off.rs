//! The storage-grant rows are compiled only in the agents build. This module
//! is that build's absence: cargo lists the ignored row and gives the reason.
#![cfg(not(feature = "prototype-agents"))]

#[test]
#[ignore = "agents are not built into this Runtime, so the storage rows are not compiled"]
fn instance_storage_rows_are_not_compiled() {
    let reason =
        crate::agents::require_build().expect_err("this build does not include the storage rows");
    eprintln!("instance_storage_rows is not compiled: {reason}");
}
