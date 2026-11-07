//! Harness self-tests: each journey against the reference double. The honest
//! double passes every journey; each fault is refused for its own reason.
//! These rows prove the harness, not the Runtime, and count toward no M1 check.

mod common;

use common::double::{Double, Faults};
use resident_instances::capability::Check;
use resident_instances::journey::Outcome;

fn run(check: Check, faults: Faults) -> (Outcome, Double) {
    let mut double = Double::new(faults);
    let outcome = check.run(&mut double);
    (outcome, double)
}

fn refused(check: Check, faults: Faults, reason: &str) {
    let (outcome, double) = run(check, faults);
    let failure = outcome.expect_err("the journey must refuse this Runtime");
    assert!(
        failure.contains(reason),
        "{} refused for another reason.\nexpected: {reason}\nactual:   {failure}",
        check.id()
    );
    assert_eq!(
        double.live_instances(),
        0,
        "a refused journey stops what it launched"
    );
}

#[test]
fn honest_double_passes_every_journey() {
    for check in Check::ALL {
        let (outcome, double) = run(check, Faults::default());
        let evidence = outcome.unwrap_or_else(|reason| panic!("{}: {reason}", check.id()));
        assert!(
            evidence.starts_with(&format!("{}:", check.id())),
            "{evidence}"
        );
        assert!(evidence.contains("census: live instances 0"), "{evidence}");
        assert_eq!(double.live_instances(), 0, "{}", check.id());
    }
}

#[test]
fn launch_refuses_an_answer_after_the_run() {
    let faults = Faults {
        launch_completes: true,
        ..Faults::default()
    };
    for check in Check::ALL {
        refused(
            check,
            faults,
            "returned completed, which is not a resident instance status",
        );
    }
}

#[test]
fn launch_refuses_a_shared_session() {
    let faults = Faults {
        shared_session: true,
        ..Faults::default()
    };
    refused(Check::A3, faults, "two instances share one Bus session");
}

#[test]
fn a3_refuses_instances_that_leave_after_start() {
    let faults = Faults {
        brief_residency: true,
        ..Faults::default()
    };
    refused(
        Check::A3,
        faults,
        "instance-1 was stopped after start returned and the dwell passed; expected running",
    );
}

#[test]
fn a3_refuses_a_process_per_instance() {
    let faults = Faults {
        process_per_instance: true,
        ..Faults::default()
    };
    refused(
        Check::A3,
        faults,
        "the two instances added 2 processes below the Runtime",
    );
}

#[test]
fn a6_refuses_a_grant_shared_across_instances() {
    let faults = Faults {
        grant_covers_siblings: true,
        ..Faults::default()
    };
    refused(
        Check::A6,
        faults,
        "the request from instance-2 for the same resource left the pending list while the grant of instance-1 was live",
    );
}

#[test]
fn a6_refuses_a_blind_grant_view() {
    let faults = Faults {
        blind_grant_census: true,
        ..Faults::default()
    };
    refused(
        Check::A6,
        faults,
        "live grants after instance-1's grant: []; expected one read grant bound to instance-1",
    );
}

#[test]
fn a10_refuses_a_stop_that_stops_the_sibling() {
    let faults = Faults {
        stop_stops_all: true,
        ..Faults::default()
    };
    refused(
        Check::A10,
        faults,
        "instance-2 was stopped after instance-1 was cancelled; expected live",
    );
}

#[test]
fn a10_refuses_a_stop_that_leaves_the_request_pending() {
    let faults = Faults {
        stop_leaves_pending: true,
        ..Faults::default()
    };
    refused(
        Check::A10,
        faults,
        "the Runtime's settlement of the request from instance-1: not seen within 10s",
    );
}

#[test]
fn a10_refuses_a_stop_without_its_reason() {
    let faults = Faults {
        stop_drops_reason: true,
        ..Faults::default()
    };
    refused(
        Check::A10,
        faults,
        "instance-1 stopped with cause \"stopped\", which omits the stop reason \"harness cancel: instance-1 cancelled mid-run\"",
    );
}

#[test]
fn a10_and_a11_refuse_a_settlement_without_its_reason() {
    let faults = Faults {
        settlement_drops_reason: true,
        ..Faults::default()
    };
    refused(
        Check::A10,
        faults,
        "the Runtime's denial for instance-1 reads \"denied\", which omits \"harness cancel: instance-1 cancelled mid-run\"",
    );
    refused(
        Check::A11,
        faults,
        "the Runtime's denial for instance-1 reads \"denied\", which omits \"wasm trap:",
    );
}

#[test]
fn a10_refuses_a_retry_after_stop() {
    let faults = Faults {
        retry_after_stop: true,
        ..Faults::default()
    };
    refused(
        Check::A10,
        faults,
        "instance-1 made a request after it ended",
    );
}

#[test]
fn a11_refuses_a_request_left_pending_by_failure() {
    let faults = Faults {
        failure_leaves_pending: true,
        ..Faults::default()
    };
    refused(
        Check::A11,
        faults,
        "the Runtime's settlement of the request from instance-1: not seen within 10s",
    );
}

#[test]
fn a11_refuses_settlement_by_the_shell() {
    let faults = Faults {
        shell_settles_failure: true,
        ..Faults::default()
    };
    refused(
        Check::A11,
        faults,
        "the request from instance-1 was settled by Some(Shell), not by the Runtime",
    );
}

#[test]
fn a12_refuses_a_blind_grant_census() {
    let faults = Faults {
        blind_grant_census: true,
        ..Faults::default()
    };
    refused(
        Check::A12,
        faults,
        "the live-grant view showed 0 grants for the two running instances",
    );
}

#[test]
fn a12_refuses_grants_kept_after_stop() {
    let faults = Faults {
        stop_keeps_grants: true,
        ..Faults::default()
    };
    refused(
        Check::A12,
        faults,
        "live grant leftover: read localhost://Public/resident-instances/shared.txt for instance-1",
    );
}

#[test]
fn census_refuses_a_process_left_after_stop() {
    let faults = Faults {
        process_leak_on_stop: true,
        ..Faults::default()
    };
    for check in Check::ALL {
        refused(check, faults, "process leftover: ");
    }
}

#[test]
fn every_journey_refuses_a_stop_that_does_nothing() {
    let faults = Faults {
        stop_ignored: true,
        ..Faults::default()
    };
    for check in Check::ALL {
        let (outcome, _) = run(check, faults);
        let failure = outcome.expect_err("a stop that does nothing must fail the journey");
        assert!(
            failure.contains(" stopped: not seen within 10s"),
            "{failure}"
        );
    }
}
