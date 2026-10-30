//! The guard against a simulated kernel: each missing layer is injected on its
//! own, for each provider, and the guard must refuse with a reason and the
//! provider image must never run.

mod common;

use std::process::Command;

use common::*;
use fail_closed_linux::{
    Fault, FsRules, Guard, LaunchError, Layer, Policy, ProviderKind, REASON_PREFIX,
    REQUIRED_LANDLOCK_ABI,
};

const GOOD_ABI: u32 = 6;

struct Refused {
    fault: Fault,
    layer: Layer,
    summary_has: &'static str,
}

/// Inject `failing`, launch every provider kind, and check the refusal.
fn assert_refused(failing: &[(Call, i32)], abi: u32, last_call: Call, expect: &Refused) {
    for provider in ProviderKind::ALL {
        let storage = TempDir::new("refused");
        let (_log_dir, log_path, log) = call_log();
        let kernel = SimKernel::new(&log, abi, failing);
        let guard = Guard::with_kernel(kernel, Policy::baseline(FsRules::new()).unwrap());

        let result = guard.launch(provider, stand_in_command(storage.path()));
        let refusal = match result {
            Err(LaunchError::Refused(refusal)) => refusal,
            Err(other) => panic!("{}: expected a refusal, got {other}", provider.name()),
            Ok(_) => panic!(
                "{}: the provider started although a layer failed",
                provider.name()
            ),
        };

        assert_eq!(refusal.provider, provider);
        assert_eq!(refusal.fault, expect.fault, "{}", provider.name());
        assert_eq!(refusal.layer(), expect.layer);
        let reason = refusal.reason();
        assert!(reason.starts_with(REASON_PREFIX), "{reason}");
        assert!(
            reason.contains(expect.summary_has),
            "{reason:?} lacks {:?}",
            expect.summary_has
        );
        if let Some((_, errno)) = failing.iter().find(|(call, _)| *call == last_call) {
            if !matches!(expect.fault, Fault::LandlockTooOld { .. }) {
                assert_eq!(refusal.errno, *errno);
                assert!(
                    reason.contains(&std::io::Error::from_raw_os_error(*errno).to_string()),
                    "{reason}"
                );
            }
        }
        assert!(
            refusal
                .to_string()
                .starts_with(&format!("{} not started: ", provider.name())),
            "{refusal}"
        );

        assert!(
            !marker_of(storage.path()).exists(),
            "{}: the provider image ran",
            provider.name()
        );
        assert_eq!(
            storage.entries(),
            Vec::<String>::new(),
            "a refusal leaves nothing under the root"
        );
        assert_eq!(
            read_calls(&log_path),
            expected_calls_through(last_call),
            "{}: layers applied after the failing one, or the failing one skipped",
            provider.name()
        );
    }
}

#[test]
fn refuses_when_user_namespaces_are_off() {
    for errno in [libc::EPERM, libc::ENOSPC, libc::EINVAL] {
        assert_refused(
            &[(Call::UnshareUser, errno)],
            GOOD_ABI,
            Call::UnshareUser,
            &Refused {
                fault: Fault::UserNamespaceOff,
                layer: Layer::UserNamespace,
                summary_has: "linux confinement refused: user namespaces are turned off",
            },
        );
    }
}

#[test]
fn refuses_when_the_id_maps_cannot_be_written() {
    assert_refused(
        &[(Call::MapIds, libc::EACCES)],
        GOOD_ABI,
        Call::MapIds,
        &Refused {
            fault: Fault::IdMapRefused,
            layer: Layer::UserNamespace,
            summary_has: "linux confinement refused: the user namespace id maps cannot be written",
        },
    );
}

#[test]
fn refuses_when_the_capability_drop_fails() {
    for errno in [libc::EPERM, libc::ENOMEM] {
        assert_refused(
            &[(Call::DropCapabilities, errno)],
            GOOD_ABI,
            Call::DropCapabilities,
            &Refused {
                fault: Fault::CapabilityDrop,
                layer: Layer::CapabilityDrop,
                summary_has: "linux confinement refused: the capability set cannot be dropped",
            },
        );
    }
}

#[test]
fn refuses_when_no_new_privs_cannot_be_set() {
    assert_refused(
        &[(Call::NoNewPrivs, libc::EPERM)],
        GOOD_ABI,
        Call::NoNewPrivs,
        &Refused {
            fault: Fault::NoNewPrivs,
            layer: Layer::NoNewPrivs,
            summary_has: "linux confinement refused: no_new_privs cannot be set",
        },
    );
}

#[test]
fn refuses_when_seccomp_cannot_be_installed() {
    for errno in [libc::ENOSYS, libc::EINVAL, libc::EPERM] {
        assert_refused(
            &[(Call::Seccomp, errno)],
            GOOD_ABI,
            Call::Seccomp,
            &Refused {
                fault: Fault::SeccompInstall,
                layer: Layer::Seccomp,
                summary_has: "linux confinement refused: the seccomp filter cannot be installed",
            },
        );
    }
}

#[test]
fn refuses_when_landlock_is_missing() {
    for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
        assert_refused(
            &[(Call::LandlockAbi, errno)],
            GOOD_ABI,
            Call::LandlockAbi,
            &Refused {
                fault: Fault::LandlockMissing,
                layer: Layer::Landlock,
                summary_has: "linux confinement refused: the kernel has no Landlock",
            },
        );
    }
}

#[test]
fn refuses_when_the_landlock_abi_is_too_old() {
    for found in 1..=4 {
        let summary = format!(
            "linux confinement refused: the Landlock ABI cannot express the STORAGE_ROOT row (needs ABI 5, this kernel reports ABI {found})"
        );
        let summary: &'static str = Box::leak(summary.into_boxed_str());
        assert_refused(
            &[],
            found,
            Call::LandlockAbi,
            &Refused {
                fault: Fault::LandlockTooOld { found },
                layer: Layer::Landlock,
                summary_has: summary,
            },
        );
    }
}

#[test]
fn refuses_when_the_landlock_ruleset_cannot_be_applied() {
    for (call, errno) in [
        (Call::LandlockRestrict, libc::EPERM),
        (Call::LandlockRestrict, libc::ENOENT),
        (Call::LandlockAbi, libc::EPERM),
    ] {
        assert_refused(
            &[(call, errno)],
            GOOD_ABI,
            call,
            &Refused {
                fault: Fault::LandlockApply,
                layer: Layer::Landlock,
                summary_has: "linux confinement refused: the Landlock ruleset cannot be applied",
            },
        );
    }
}

#[test]
fn the_first_failing_layer_in_apply_order_is_the_one_reported() {
    assert_refused(
        &[
            (Call::LandlockAbi, libc::ENOSYS),
            (Call::DropCapabilities, libc::EPERM),
        ],
        GOOD_ABI,
        Call::DropCapabilities,
        &Refused {
            fault: Fault::CapabilityDrop,
            layer: Layer::CapabilityDrop,
            summary_has: "the capability set cannot be dropped",
        },
    );
}

#[test]
fn starts_the_provider_only_after_every_layer_applied_in_order() {
    for provider in ProviderKind::ALL {
        let storage = TempDir::new("started");
        let (_log_dir, log_path, log) = call_log();
        let guard = Guard::with_kernel(
            SimKernel::new(&log, GOOD_ABI, &[]),
            Policy::baseline(FsRules::new()).unwrap(),
        );

        let child = guard
            .launch(provider, stand_in_command(storage.path()))
            .unwrap();
        let mut session = Session::new(child);
        assert!(
            session.ask("status").contains("seccomp="),
            "the provider answers"
        );
        session.finish();

        assert!(marker_of(storage.path()).exists());
        assert_eq!(
            read_calls(&log_path),
            expected_calls_through(Call::LandlockRestrict)
        );
    }
}

#[test]
fn the_landlock_floor_cannot_be_lowered_and_can_be_raised() {
    let (_log_dir, _path, log) = call_log();
    let policy = || Policy::baseline(FsRules::new()).unwrap();

    let guard = Guard::with_kernel(SimKernel::new(&log, 4, &[]), policy()).require_landlock_abi(1);
    assert_eq!(guard.needed_landlock_abi(), 5);
    assert_eq!(REQUIRED_LANDLOCK_ABI, 5);
    let storage = TempDir::new("floor");
    match guard.launch(ProviderKind::Did, stand_in_command(storage.path())) {
        Err(LaunchError::Refused(refusal)) => {
            assert_eq!(refusal.fault, Fault::LandlockTooOld { found: 4 })
        }
        other => panic!("ABI 4 must be refused under the floor: {other:?}"),
    }
    assert!(!marker_of(storage.path()).exists());

    let guard = Guard::with_kernel(SimKernel::new(&log, 6, &[]), policy()).require_landlock_abi(7);
    assert_eq!(guard.needed_landlock_abi(), 7);
    match guard.launch(ProviderKind::Did, stand_in_command(storage.path())) {
        Err(LaunchError::Refused(refusal)) => {
            assert_eq!(refusal.fault, Fault::LandlockTooOld { found: 6 });
            assert!(
                refusal
                    .reason()
                    .contains("needs ABI 7, this kernel reports ABI 6"),
                "{refusal}"
            );
        }
        other => panic!("ABI 6 must be refused when ABI 7 is required: {other:?}"),
    }
    assert!(!marker_of(storage.path()).exists());
}

#[test]
fn a_failed_exec_after_every_layer_applied_is_a_spawn_error_not_a_refusal() {
    let (_log_dir, log_path, log) = call_log();
    let guard = Guard::with_kernel(
        SimKernel::new(&log, GOOD_ABI, &[]),
        Policy::baseline(FsRules::new()).unwrap(),
    );
    match guard.launch(ProviderKind::Wallet, Command::new("/nonexistent/provider")) {
        Err(LaunchError::Spawn(error)) => assert_eq!(error.raw_os_error(), Some(libc::ENOENT)),
        other => panic!("expected a spawn error: {other:?}"),
    }
    assert_eq!(
        read_calls(&log_path),
        expected_calls_through(Call::LandlockRestrict)
    );
}

#[test]
fn a_layer_failure_wins_over_a_missing_executable() {
    let (_log_dir, _path, log) = call_log();
    let kernel = SimKernel::new(&log, GOOD_ABI, &[(Call::Seccomp, libc::ENOSYS)]);
    let guard = Guard::with_kernel(kernel, Policy::baseline(FsRules::new()).unwrap());
    match guard.launch(ProviderKind::Model, Command::new("/nonexistent/provider")) {
        Err(LaunchError::Refused(refusal)) => assert_eq!(refusal.fault, Fault::SeccompInstall),
        other => panic!("expected a refusal: {other:?}"),
    }
}

#[test]
fn a_fault_survives_the_trip_through_the_spawn_error() {
    let faults = [
        Fault::UserNamespaceOff,
        Fault::IdMapRefused,
        Fault::CapabilityDrop,
        Fault::NoNewPrivs,
        Fault::SeccompInstall,
        Fault::LandlockMissing,
        Fault::LandlockTooOld { found: 4 },
        Fault::LandlockApply,
    ];
    for fault in faults {
        for errno in [0, 1, libc::ENOSPC, 133] {
            let wire = fault.to_wire(errno);
            assert!(wire > 0);
            assert_eq!(Fault::from_wire(wire), Some((fault, errno)));
        }
    }
}

#[test]
fn an_ordinary_exec_error_is_never_read_as_a_fault() {
    for errno in [
        libc::ENOENT,
        libc::EACCES,
        libc::ENOEXEC,
        libc::E2BIG,
        libc::ENOMEM,
        libc::EPERM,
    ] {
        assert_eq!(Fault::from_wire(errno), None, "errno {errno}");
    }
}

#[test]
fn reason_lines_match_the_linux_design_doc() {
    let doc_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsules/wallet-provider/CONFINEMENT-LINUX.md"
    );
    let doc =
        std::fs::read_to_string(doc_path).unwrap_or_else(|error| panic!("{doc_path}: {error}"));
    let doc = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    for fault in [
        Fault::UserNamespaceOff,
        Fault::CapabilityDrop,
        Fault::NoNewPrivs,
        Fault::SeccompInstall,
        Fault::LandlockMissing,
    ] {
        let summary = fault.summary(REQUIRED_LANDLOCK_ABI);
        assert!(
            doc.contains(&format!("`{summary}`")),
            "the design doc does not give {summary:?}"
        );
    }
    let too_old = Fault::LandlockTooOld { found: 1 }.summary(REQUIRED_LANDLOCK_ABI);
    let stem = "linux confinement refused: the Landlock ABI cannot express";
    assert!(too_old.starts_with(stem));
    assert!(
        doc.contains(&format!("`{stem} <row>`")),
        "the design doc does not give the ABI refusal"
    );
}
