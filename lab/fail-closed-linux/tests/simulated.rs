//! Refusal rows on the simulated kernel, for the did, wallet and model
//! providers. Each row fails one step and checks that the refusal names the
//! provider, layer, step and OS error, that no later step ran, and that
//! nothing was executed.

mod common;

use common::{probe, PROVIDERS};
use fail_closed_linux::sim::{SimKernel, SIM_PID};
use fail_closed_linux::{
    file_profile_launches_on_abi, handled_fs_for_abi, handled_net_for_abi, landlock, launch,
    missing_required_mask, scoped_for_abi, Errno, Kernel, Layer, ProviderSpec, Refusal, Step,
    MISSING_IOCTL_DEV, MISSING_TEST_FUTURE_FS, MISSING_TRUNCATE, PID_NAMESPACE_UNAVAILABLE,
    TEST_FUTURE_FS_ABI, TEST_FUTURE_FS_NAME,
};

fn spec(provider: &str) -> ProviderSpec {
    ProviderSpec::new(
        provider,
        probe(),
        format!("/srv/fcl-sim/{provider}/storage"),
    )
}

fn refused(kernel: &mut SimKernel, spec: &ProviderSpec) -> Refusal {
    match launch(kernel, spec) {
        Ok(started) => panic!(
            "{} started as pid {} although the kernel was set to fail; steps {:?}",
            spec.name(),
            started.pid,
            kernel.steps
        ),
        Err(refusal) => refusal,
    }
}

fn assert_stopped_at(refusal: &Refusal, kernel: &SimKernel, provider: &str, step: Step) {
    let context = format!("{refusal}\nsteps {:?}", kernel.steps);
    assert_eq!(refusal.provider, provider, "{context}");
    assert_eq!(refusal.layer, step.layer(), "{context}");
    assert_eq!(refusal.step, step, "{context}");
    let text = refusal.to_string();
    for part in [
        format!("refused to start {provider}"),
        format!("layer {}", step.layer()),
        format!("step {step}"),
        "the provider was not started".to_string(),
    ] {
        assert!(text.contains(&part), "missing {part:?} in {text:?}");
    }
    assert!(
        kernel.execs.is_empty(),
        "exec ran after a refusal: {context}"
    );
    if step != Step::Execve {
        assert!(!kernel.steps.contains(&Step::Execve), "{context}");
    }
    if step != Step::AbiFloor {
        assert_eq!(
            kernel.steps.last(),
            Some(&step),
            "a step ran after {step}: {context}"
        );
    }
}

/// One OS-error row: every provider, every listed step and errno.
fn os_error_row(rows: &[(Step, Errno)]) {
    for provider in PROVIDERS {
        for &(step, errno) in rows {
            let mut kernel = SimKernel::failing(step, errno);
            let refusal = refused(&mut kernel, &spec(provider));
            assert_stopped_at(&refusal, &kernel, provider, step);
            assert_eq!(refusal.errno, Some(errno), "{refusal}");
            let os_error = format!("(os error {errno})");
            assert!(
                refusal.to_string().contains(&os_error),
                "missing {os_error}: {refusal}"
            );
        }
    }
}

#[test]
fn sim_user_namespaces_off_refuses() {
    os_error_row(&[(Step::Unshare, libc::EPERM), (Step::Unshare, libc::ENOSPC)]);
}

#[test]
fn sim_pid_namespace_unavailable_refuses() {
    os_error_row(&[
        (Step::UnsharePid, libc::EPERM),
        (Step::UnsharePid, libc::ENOSYS),
        (Step::UnsharePid, libc::ENOSPC),
    ]);
    let mut kernel = SimKernel::failing(Step::UnsharePid, libc::EPERM);
    let refusal = refused(&mut kernel, &spec("did-provider"));
    assert_eq!(refusal.layer, Layer::PidNamespace, "{refusal}");
    assert_eq!(refusal.step, Step::UnsharePid, "{refusal}");
    let text = refusal.to_string();
    assert!(
        text.contains(PID_NAMESPACE_UNAVAILABLE),
        "missing {PID_NAMESPACE_UNAVAILABLE:?}: {refusal}"
    );
    assert!(
        !kernel.steps.contains(&Step::LastCapability),
        "capabilities ran after a PID-namespace refusal: {:?}",
        kernel.steps
    );
}

#[test]
fn sim_id_maps_unwritable_refuses() {
    os_error_row(&[
        (Step::UidMap, libc::EACCES),
        (Step::Setgroups, libc::EACCES),
        (Step::GidMap, libc::EPERM),
    ]);
}

#[test]
fn sim_capability_drop_failure_refuses() {
    os_error_row(&[
        (Step::LastCapability, libc::ENOENT),
        (Step::BoundingSet, libc::EPERM),
        (Step::AmbientSet, libc::EINVAL),
        (Step::CapabilitySets, libc::EPERM),
    ]);
}

#[test]
fn sim_no_new_privs_failure_refuses() {
    os_error_row(&[(Step::SetNoNewPrivs, libc::EINVAL)]);
}

#[test]
fn sim_seccomp_install_failure_refuses() {
    os_error_row(&[
        (Step::InstallFilter, libc::EINVAL),
        (Step::InstallFilter, libc::ENOSYS),
    ]);
}

#[test]
fn sim_no_exec_filter_failure_refuses() {
    os_error_row(&[
        (Step::InstallNoExec, libc::EINVAL),
        (Step::InstallNoExec, libc::ENOSYS),
    ]);
    let mut kernel = SimKernel::failing(Step::InstallNoExec, libc::ENOSYS);
    let refusal = refused(&mut kernel, &spec("did-provider"));
    assert!(
        refusal
            .to_string()
            .contains("the no-exec seccomp filter could not be installed"),
        "{refusal}"
    );
}

#[test]
fn sim_stdio_sanitize_failure_refuses() {
    os_error_row(&[(Step::SanitizeStdio, libc::EPERM)]);
    let mut kernel = SimKernel::failing(Step::SanitizeStdio, libc::EPERM);
    let refusal = refused(&mut kernel, &spec("did-provider"));
    assert!(
        refusal
            .to_string()
            .contains("fd 0 is a terminal and could not be replaced"),
        "{refusal}"
    );
}

#[test]
fn sim_landlock_missing_refuses() {
    os_error_row(&[
        (Step::AbiProbe, libc::ENOSYS),
        (Step::AbiProbe, libc::EOPNOTSUPP),
    ]);
    let mut kernel = SimKernel::failing(Step::AbiProbe, libc::ENOSYS);
    let refusal = refused(&mut kernel, &spec("did-provider"));
    assert!(
        refusal.to_string().contains("Landlock is not available"),
        "{refusal}"
    );
}

#[test]
fn sim_landlock_abi_too_old_refuses() {
    for provider in PROVIDERS {
        for abi in 1..5 {
            let mut kernel = SimKernel::with_landlock_abi(abi);
            let refusal = refused(&mut kernel, &spec(provider));
            assert_stopped_at(&refusal, &kernel, provider, Step::AbiFloor);
            let mask = missing_required_mask(abi).expect("ABI 1-4 lack a needed right");
            assert_eq!(refusal.errno, Some(mask), "{refusal}");
            let text = refusal.to_string();
            assert!(
                text.contains(&format!("this kernel's Landlock ABI {abi} cannot deny")),
                "{refusal}"
            );
            if abi < 3 {
                assert!(text.contains("truncate (needs ABI 3)"), "{refusal}");
            } else {
                assert!(!text.contains("truncate"), "{refusal}");
            }
            assert!(text.contains("ioctl_dev (needs ABI 5)"), "{refusal}");
            assert!(
                !kernel.steps.contains(&Step::CreateRuleset),
                "{:?}",
                kernel.steps
            );
        }
        let mut kernel = SimKernel::with_landlock_abi(6);
        let refusal = refused(&mut kernel, &spec(provider).require_landlock_abi(7));
        assert_stopped_at(&refusal, &kernel, provider, Step::AbiFloor);
        assert_eq!(refusal.errno, None, "{refusal}");
        assert!(
            refusal
                .to_string()
                .contains("Landlock ABI 6 is below the required 7"),
            "{refusal}"
        );
    }
}

#[test]
fn sim_landlock_ruleset_unappliable_refuses() {
    os_error_row(&[
        (Step::CreateRuleset, libc::EINVAL),
        (Step::StorageRootRule, libc::ENOENT),
        (Step::ExecutableRule, libc::EACCES),
        (Step::RestrictSelf, libc::E2BIG),
    ]);
}

#[test]
fn sim_landlock_abi_floor_cannot_be_lowered() {
    let mut kernel = SimKernel::with_landlock_abi(4);
    let refusal = refused(&mut kernel, &spec("model-provider").require_landlock_abi(3));
    assert_stopped_at(&refusal, &kernel, "model-provider", Step::AbiFloor);
    assert_eq!(refusal.errno, Some(MISSING_IOCTL_DEV), "{refusal}");
    assert!(
        refusal
            .to_string()
            .contains("this kernel's Landlock ABI 4 cannot deny ioctl_dev (needs ABI 5)"),
        "{refusal}"
    );
    assert!(
        !kernel.steps.contains(&Step::CreateRuleset),
        "{:?}",
        kernel.steps
    );
}

#[test]
fn sim_every_guard_step_failure_stops_before_exec() {
    for step in Step::GUARD {
        if step == Step::AbiFloor {
            continue;
        }
        let mut kernel = SimKernel::failing(step, libc::EPERM);
        let refusal = refused(&mut kernel, &spec("wallet-provider"));
        assert_stopped_at(&refusal, &kernel, "wallet-provider", step);
    }
}

#[test]
fn sim_confined_provider_starts_after_every_layer() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::new();
        let started = launch(&mut kernel, &spec(provider)).expect("no step failed");
        assert_eq!(started.provider, provider);
        assert_eq!(started.pid, SIM_PID);
        assert_eq!(kernel.execs.len(), 1, "{:?}", kernel.execs);
        assert_eq!(
            kernel.execs[0].to_bytes(),
            probe().as_os_str().as_encoded_bytes()
        );

        let mut layers: Vec<Layer> = kernel.steps.iter().map(|step| step.layer()).collect();
        layers.dedup();
        assert_eq!(
            layers,
            [
                Layer::UserNamespace,
                Layer::PidNamespace,
                Layer::Capabilities,
                Layer::NoNewPrivs,
                Layer::Seccomp,
                Layer::Landlock,
                Layer::Launch,
                Layer::Landlock,
                Layer::Launch,
                Layer::Seccomp,
                Layer::Landlock,
                Layer::Exec,
            ],
            "steps {:?}",
            kernel.steps
        );
        let drops = kernel
            .steps
            .iter()
            .filter(|step| **step == Step::BoundingSet)
            .count();
        assert_eq!(
            drops,
            kernel.last_capability as usize + 1,
            "one drop per capability"
        );
        let expected: Vec<Step> = Step::GUARD
            .iter()
            .copied()
            .filter(|step| *step != Step::AbiFloor)
            .collect();
        let mut seen = kernel.steps.clone();
        seen.dedup();
        assert_eq!(seen, expected, "every guard step ran once, in order");
        assert_eq!(kernel.handled_fs, handled_fs_for_abi(6));
        assert_eq!(kernel.handled_net, handled_net_for_abi(6));
        assert_eq!(kernel.scoped, landlock::SCOPE_SIGNAL);
    }
}

#[test]
fn sim_per_right_floor_for_each_abi() {
    for provider in PROVIDERS {
        for abi in 1..=6 {
            let mut kernel = SimKernel::with_landlock_abi(abi);
            if file_profile_launches_on_abi(abi) {
                let started = launch(&mut kernel, &spec(provider)).expect("needed rights present");
                assert_eq!(started.provider, provider);
                assert_eq!(kernel.execs.len(), 1, "abi {abi} {:?}", kernel.execs);
                assert_eq!(kernel.handled_fs, handled_fs_for_abi(abi), "abi {abi}");
                assert_eq!(kernel.handled_net, handled_net_for_abi(abi), "abi {abi}");
                assert_eq!(kernel.scoped, scoped_for_abi(abi), "abi {abi}");
                assert_eq!(
                    kernel.handled_fs & landlock::ACCESS_FS_IOCTL_DEV != 0,
                    abi >= 5,
                    "abi {abi} must not invent ioctl_dev"
                );
                if abi >= 6 {
                    assert_eq!(
                        kernel.scoped,
                        landlock::SCOPE_SIGNAL,
                        "{provider} abi {abi}"
                    );
                } else {
                    assert_eq!(kernel.scoped, 0, "{provider} abi {abi}");
                }
            } else {
                let refusal = refused(&mut kernel, &spec(provider));
                assert_stopped_at(&refusal, &kernel, provider, Step::AbiFloor);
                let mask = missing_required_mask(abi).expect("a missing right");
                assert_eq!(refusal.errno, Some(mask), "{refusal}");
                assert!(
                    !kernel.steps.contains(&Step::CreateRuleset),
                    "abi {abi} created a ruleset after a missing right: {:?}",
                    kernel.steps
                );
                assert!(
                    kernel.execs.is_empty(),
                    "abi {abi} execs {:?}",
                    kernel.execs
                );
            }
        }
    }
}

#[test]
fn sim_missing_right_is_never_silently_dropped() {
    for provider in PROVIDERS {
        for abi in 1..=4 {
            let mut kernel = SimKernel::with_landlock_abi(abi);
            let refusal = refused(&mut kernel, &spec(provider));
            assert_eq!(refusal.step, Step::AbiFloor, "{refusal}");
            assert_ne!(
                refusal.errno, None,
                "a missing right must be named, not passed: {refusal}"
            );
            let text = refusal.to_string();
            assert!(text.contains("cannot deny"), "{refusal}");
            if abi < 3 {
                assert_eq!(
                    refusal.errno,
                    Some(MISSING_TRUNCATE | MISSING_IOCTL_DEV),
                    "{refusal}"
                );
            } else {
                assert_eq!(refusal.errno, Some(MISSING_IOCTL_DEV), "{refusal}");
            }
            assert!(
                kernel.execs.is_empty(),
                "abi {abi} started after dropping a right: {:?}",
                kernel.execs
            );
        }
    }
}

#[test]
fn sim_add_path_rule_rejects_access_outside_handled_fs() {
    let mut kernel = SimKernel::new();
    let fd = kernel
        .landlock_create_ruleset(handled_fs_for_abi(1), 0, 0)
        .expect("ABI 1 ruleset");
    let err = kernel
        .landlock_add_path_rule(fd, c"/srv/storage", landlock::STORAGE_ROOT_ACCESS)
        .expect_err("TRUNCATE is outside ABI 1 handled_fs");
    assert_eq!(err, libc::EINVAL);
    assert_eq!(kernel.steps.last(), Some(&Step::StorageRootRule));

    let mut kernel = SimKernel::new();
    let fd = kernel
        .landlock_create_ruleset(handled_fs_for_abi(1), 0, 0)
        .expect("ABI 1 ruleset");
    kernel
        .landlock_add_path_rule(fd, c"/bin/probe", landlock::EXECUTABLE_ACCESS)
        .expect("EXECUTE|READ is inside ABI 1 handled_fs");
}

#[test]
fn sim_extra_floor_still_names_the_missing_right() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(4);
        let refusal = refused(&mut kernel, &spec(provider).require_landlock_abi(6));
        assert_stopped_at(&refusal, &kernel, provider, Step::AbiFloor);
        assert_eq!(refusal.errno, Some(MISSING_IOCTL_DEV), "{refusal}");
        let text = refusal.to_string();
        assert!(text.contains("ioctl_dev (needs ABI 5)"), "{refusal}");
        assert!(text.contains("cannot deny"), "{refusal}");
        assert!(
            text.contains("Landlock ABI 4 is below the required 6"),
            "{refusal}"
        );
        assert!(kernel.execs.is_empty(), "{:?}", kernel.execs);
    }
}

#[test]
fn sim_lying_abi_5_with_abi_1_rights_refuses() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(5);
        kernel.accepted_fs = Some(handled_fs_for_abi(1));
        let refusal = refused(&mut kernel, &spec(provider));
        assert_eq!(refusal.layer, Layer::Landlock, "{refusal}");
        assert_eq!(refusal.step, Step::RightProbe, "{refusal}");
        let text = refusal.to_string();
        assert!(
            text.contains("landlock_create_ruleset returned EINVAL"),
            "{refusal}"
        );
        assert!(text.contains("reported ABI 5"), "{refusal}");
        assert!(text.contains("truncate"), "{refusal}");
        assert!(text.contains("ioctl_dev"), "{refusal}");
        assert!(
            kernel.execs.is_empty(),
            "{provider} started on a lying ABI: {:?}",
            kernel.execs
        );
        assert!(!kernel.steps.contains(&Step::Execve), "{:?}", kernel.steps);
        assert!(
            !kernel.steps.contains(&Step::CreateRuleset),
            "{:?}",
            kernel.steps
        );
    }
}

#[test]
fn sim_test_extra_right_refuses_on_abi_6() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(6);
        let refusal = refused(
            &mut kernel,
            &spec(provider).require_test_right(MISSING_TEST_FUTURE_FS),
        );
        assert_stopped_at(&refusal, &kernel, provider, Step::AbiFloor);
        assert_eq!(refusal.errno, Some(MISSING_TEST_FUTURE_FS), "{refusal}");
        let text = refusal.to_string();
        assert!(
            text.contains(&format!(
                "this kernel's Landlock ABI 6 cannot deny {TEST_FUTURE_FS_NAME} (needs ABI {TEST_FUTURE_FS_ABI})"
            )),
            "{refusal}"
        );
        assert!(
            !kernel.steps.contains(&Step::CreateRuleset),
            "{:?}",
            kernel.steps
        );
    }
}

#[test]
fn sim_lying_kernel_enforcement_refuses() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(6);
        kernel.lie_enforcement = true;
        let refusal = refused(&mut kernel, &spec(provider));
        assert_eq!(refusal.layer, Layer::Landlock, "{refusal}");
        assert_eq!(refusal.step, Step::EnforceSelf, "{refusal}");
        let text = refusal.to_string();
        assert!(
            text.contains("Landlock accepted a right and did not enforce it"),
            "{refusal}"
        );
        assert!(
            kernel.execs.is_empty(),
            "{provider} started on a lying kernel: {:?}",
            kernel.execs
        );
        assert!(!kernel.steps.contains(&Step::Execve), "{:?}", kernel.steps);
    }
}
