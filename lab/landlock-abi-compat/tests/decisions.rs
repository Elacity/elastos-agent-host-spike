//! Simulated ABI levels. No kernel calls.

use landlock_abi_compat::{
    bits, decide_best_effort, decide_compensated, decide_guard_299, decide_guard_307,
    decide_hard_floor, decide_per_row, is_silently_weaker, landlock_expresses_deny_network,
    missing_required, ruleset_299, ruleset_307, signal_row_confined, Controls, Decision,
    GUARD_FLOOR_ABI, IOCTL_DEV_ABI, TRUNCATE_ABI,
};

fn levels() -> impl Iterator<Item = Option<u32>> {
    [None].into_iter().chain((1..=8).map(Some))
}

fn reason(decision: &Decision) -> String {
    match decision {
        Decision::Refuse { reason } => reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn guards_and_per_row_never_start_with_a_missing_required_right() {
    for abi in levels() {
        for decision in [
            decide_guard_299(abi),
            decide_guard_307(abi),
            decide_per_row(abi),
            decide_hard_floor(abi),
        ] {
            assert!(
                !is_silently_weaker(&decision, abi),
                "abi {abi:?} decided {decision:?}"
            );
        }
    }
}

#[test]
fn per_row_refuses_below_abi_5() {
    for abi in [None, Some(1), Some(2), Some(3), Some(4)] {
        let decision = decide_per_row(abi);
        assert!(
            matches!(decision, Decision::Refuse { .. }),
            "abi {abi:?} decided {decision:?}"
        );
        assert!(!is_silently_weaker(&decision, abi));
    }
    for abi in [Some(5), Some(6), Some(7)] {
        assert_eq!(decide_per_row(abi), Decision::RunConfined);
        assert_eq!(decide_guard_299(abi), Decision::RunConfined);
        assert_eq!(decide_guard_307(abi), Decision::RunConfined);
    }
}

#[test]
fn abi_4_refuses_for_ioctl_dev_and_not_for_truncate_or_refer() {
    let decision = decide_per_row(Some(4));
    let text = reason(&decision);
    assert!(text.contains("IOCTL_DEV"), "{text}");
    assert!(!text.contains("TRUNCATE"), "{text}");
    assert!(!text.contains("REFER"), "{text}");
    assert!(reason(&decide_guard_299(Some(4))).contains("needs ABI 5"));
    assert!(reason(&decide_guard_307(Some(4))).contains("below the required 5"));
}

#[test]
fn abi_2_names_truncate_and_ioctl_and_does_not_name_refer() {
    let text = reason(&decide_per_row(Some(2)));
    assert!(text.contains("TRUNCATE"), "{text}");
    assert!(text.contains("IOCTL_DEV"), "{text}");
    assert!(!text.contains("REFER"), "{text}");
    let names: Vec<_> = missing_required(Some(2))
        .iter()
        .map(|right| right.name)
        .collect();
    assert_eq!(names, vec!["TRUNCATE", "IOCTL_DEV"]);
}

#[test]
fn absent_landlock_refuses_and_names_the_filesystem_rights() {
    assert_eq!(
        decide_guard_299(None),
        Decision::Refuse {
            reason: "the kernel has no Landlock".to_string(),
        }
    );
    assert_eq!(
        decide_guard_307(None),
        Decision::Refuse {
            reason: "Landlock is not available".to_string(),
        }
    );
    let text = reason(&decide_per_row(None));
    assert!(text.contains("filesystem rights"), "{text}");
    assert!(text.contains("TRUNCATE"), "{text}");
    assert!(text.contains("IOCTL_DEV"), "{text}");
}

#[test]
fn best_effort_runs_weaker_whenever_a_required_right_is_missing() {
    for abi in [None, Some(1), Some(2), Some(3), Some(4)] {
        let decision = decide_best_effort(abi);
        assert!(
            matches!(decision, Decision::RunWeaker { .. }),
            "abi {abi:?} decided {decision:?}"
        );
        assert!(is_silently_weaker(&decision, abi));
    }
    assert_eq!(
        decide_best_effort(Some(GUARD_FLOOR_ABI)),
        Decision::RunConfined
    );
    assert!(!is_silently_weaker(&decide_best_effort(Some(6)), Some(6)));
}

#[test]
fn best_effort_on_abi_1_drops_truncate_and_ioctl_dev() {
    match decide_best_effort(Some(1)) {
        Decision::RunWeaker { missing } => {
            assert_eq!(missing, vec!["TRUNCATE", "IOCTL_DEV"]);
        }
        other => panic!("expected a weaker start, got {other:?}"),
    }
    // ABI 1 has the base filesystem rights, so the hole that remains after the
    // base mask is truncate and ioctl. The required list still includes the
    // base rights only when the ABI is below 1.
    assert!(missing_required(Some(1))
        .iter()
        .any(|right| right.minimum_abi == TRUNCATE_ABI));
    assert!(missing_required(Some(1))
        .iter()
        .any(|right| right.minimum_abi == IOCTL_DEV_ABI));
}

#[test]
fn a_run_confined_result_with_a_missing_right_is_still_silently_weaker() {
    // The planted mutation returns this shape: it claims a confined start
    // after throwing the missing-right list away.
    let claimed = Decision::RunConfined;
    assert!(is_silently_weaker(&claimed, Some(4)));
    assert!(is_silently_weaker(&claimed, None));
    assert!(!is_silently_weaker(&claimed, Some(5)));
}

#[test]
fn compensation_runs_on_abi_1_only_when_every_control_is_present() {
    assert_eq!(
        decide_compensated(Some(1), Controls::ALL),
        Decision::RunConfined
    );
    let no_mount = Controls {
        mount_namespace_hides_host_files: false,
        ..Controls::ALL
    };
    let text = reason(&decide_compensated(Some(1), no_mount));
    assert!(text.contains("TRUNCATE"), "{text}");
    assert!(text.contains("IOCTL_DEV"), "{text}");

    let device_left_in_storage = Controls {
        storage_root_has_no_device_node: false,
        ..Controls::ALL
    };
    let text = reason(&decide_compensated(Some(1), device_left_in_storage));
    assert!(text.contains("IOCTL_DEV"), "{text}");
    assert!(!text.contains("TRUNCATE"), "{text}");
}

#[test]
fn compensation_still_refuses_network_when_seccomp_does_not_deny_socket() {
    for abi in [None, Some(1), Some(5), Some(6)] {
        assert!(!landlock_expresses_deny_network(abi));
        let controls = Controls {
            seccomp_denies_socket: false,
            ..Controls::ALL
        };
        let text = reason(&decide_compensated(abi, controls));
        assert!(text.contains("network"), "abi {abi:?}: {text}");
    }
}

#[test]
fn abi_5_with_seccomp_needs_no_mount_namespace() {
    let controls = Controls {
        seccomp_denies_socket: true,
        ..Controls::NONE
    };
    assert_eq!(decide_compensated(Some(5), controls), Decision::RunConfined);
    assert_eq!(decide_compensated(Some(6), controls), Decision::RunConfined);
}

#[test]
fn no_control_at_all_refuses_even_at_abi_6_because_network_is_open() {
    let text = reason(&decide_compensated(Some(6), Controls::NONE));
    assert!(text.contains("network"), "{text}");
    assert!(!text.contains("TRUNCATE"), "{text}");
    assert!(!text.contains("IOCTL_DEV"), "{text}");
}

#[test]
fn draft_rulesets_differ_once_they_run() {
    let older = ruleset_299();
    let newer = ruleset_307();
    assert_eq!(older.handled_fs, bits::FS_ABI5_ALL);
    assert_eq!(newer.handled_fs, bits::FS_ABI5_ALL);
    assert_eq!(older.executable, bits::FS_EXECUTE | bits::FS_READ_FILE);
    assert_eq!(newer.executable, older.executable);

    assert_ne!(older.storage & bits::FS_IOCTL_DEV, 0);
    assert_ne!(older.storage & bits::FS_REFER, 0);
    assert_ne!(older.storage & bits::FS_MAKE_CHAR, 0);
    assert_ne!(older.storage & bits::FS_MAKE_BLOCK, 0);
    assert_ne!(older.storage & bits::FS_MAKE_SYM, 0);
    assert_eq!(older.handled_net, 0);
    assert_eq!(older.scoped, 0);

    assert_eq!(newer.storage & bits::FS_IOCTL_DEV, 0);
    assert_eq!(newer.storage & bits::FS_REFER, 0);
    assert_eq!(newer.storage & bits::FS_MAKE_CHAR, 0);
    assert_eq!(newer.storage & bits::FS_MAKE_SOCK, 0);
    assert_eq!(newer.storage & bits::FS_MAKE_FIFO, 0);
    assert_eq!(newer.storage & bits::FS_MAKE_BLOCK, 0);
    assert_eq!(newer.storage & bits::FS_MAKE_SYM, 0);
    assert_ne!(newer.storage & bits::FS_TRUNCATE, 0);
    assert_ne!(newer.storage & bits::FS_WRITE_FILE, 0);
    assert_eq!(
        newer.handled_net,
        bits::NET_BIND_TCP | bits::NET_CONNECT_TCP
    );
    assert_eq!(newer.scoped, 0);
    assert_eq!(newer.scoped & bits::SCOPE_SIGNAL, 0);
    assert_eq!(newer.scoped & bits::SCOPE_ABSTRACT_UNIX_SOCKET, 0);
}

#[test]
fn neither_draft_confines_the_signal_row() {
    assert!(!signal_row_confined(false, false));
    assert!(signal_row_confined(true, false));
    assert!(signal_row_confined(false, true));
    assert_eq!(ruleset_299().scoped, 0);
    assert_eq!(ruleset_307().scoped, 0);
}
