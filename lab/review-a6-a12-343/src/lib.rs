//! Independent review probes for draft PR #343.
//!
//! The functions under test are byte copies of `lab/a6-a12-evidence-fix`
//! at `011d01f283a3f4ed4717383ecedf55622d451b4d`. This crate does not
//! edit that branch.

#[path = "../subject/a12.rs"]
mod a12;
#[path = "../subject/a6.rs"]
mod a6;

mod existing;

#[cfg(test)]
mod holds {
    use super::{a12, a6, existing};

    #[test]
    fn a6_owner_and_sibling_mock_match_the_claimed_lines() {
        let owner = a6::owner_may_use_own_token().expect("owner");
        assert!(
            owner.contains("instance-1 may use its session token"),
            "{owner}"
        );
        let refusal = a6::sibling_presenting_owner_token_is_refused().expect("sibling");
        assert!(refusal.contains("wrong_capsule"), "{refusal}");
        assert!(refusal.contains("expected:instance-1"), "{refusal}");
        assert!(refusal.contains("got:instance-2"), "{refusal}");
    }

    #[test]
    fn a6_sibling_wrapper_rejects_a_generic_denied_reason() {
        let generic = Err::<(), _>("denied".to_string());
        match generic {
            Err(reason)
                if reason.contains("wrong_capsule")
                    && reason.contains("expected:instance-1")
                    && reason.contains("got:instance-2") =>
            {
                panic!("generic denied must not satisfy the claimed reason");
            }
            other => assert!(other.is_err(), "{other:?}"),
        }
        let specific =
            a6::session_token_binds_caller("instance-1", "instance-2").expect_err("sibling bind");
        assert!(specific.contains("wrong_capsule"), "{specific}");
        assert!(specific.contains("expected:instance-1"), "{specific}");
        assert!(specific.contains("got:instance-2"), "{specific}");
        assert!(
            !specific.contains("denied"),
            "claimed reason is not the generic word denied: {specific}"
        );
    }

    #[test]
    fn a6_runtime_step4_source_pin_and_delete_falsifier() {
        let source = existing::runtime_validate_source();
        let line = a6::runtime_step4_present(source).expect("step 4 text");
        assert!(line.contains("validate step 4"), "{line}");
        let stripped = source.replace("        if token.capsule != caller_capsule_id {\n", "");
        let err = a6::runtime_step4_present(&stripped).expect_err("delete must be seen");
        assert!(err.contains("session-token check is absent"), "{err}");
    }

    #[test]
    fn existing_gap_pins_still_match_owner_sources() {
        existing::a6_journeys_omit_token_presentation().expect("A6 gap");
        existing::request_path_sends_every_request_to_pending().expect("pending path");
        existing::census_ignores_runtime_storage().expect("A12 gap");
        existing::cleanup_leftover_test_plants_only_in_home_temp().expect("TMPDIR plant");
    }

    #[test]
    fn cited_owner_snippets_exist_in_this_tree() {
        let census = include_str!("../../agent-conformance/src/census.rs");
        assert!(census.contains("pub fn cleanup("));
        assert!(census.contains("home.temp()"));
        assert!(census.contains("outside-root:BLOCKED(AC-006-STORAGE)"));
        assert!(
            !census.contains("/tmp/elastos/storage"),
            "owner census still does not name /tmp/elastos/storage"
        );

        let runtime = include_str!("../../agent-conformance/tests/runtime.rs");
        assert!(runtime.contains("fn cleanup_census_refuses_each_leftover"));
        assert!(runtime.contains("home.temp().join(\"planted\")"));

        let effects = include_str!("../../agent-conformance/tests/effects.rs");
        assert!(effects.contains("fn two_instances_overlap_with_separate_grants"));
        assert!(effects.contains("fn instance_grant_does_not_authorise_sibling"));
        for needle in [
            "WrongCapsule",
            "from_base64",
            "token.capsule",
            "caller_capsule",
        ] {
            assert!(
                !effects.contains(needle),
                "effects.rs now mentions {needle}"
            );
        }

        let grants = include_str!("../../agent-conformance/tests/common/grants.rs");
        for needle in [
            "WrongCapsule",
            "from_base64",
            "token.capsule",
            "caller_capsule",
        ] {
            assert!(!grants.contains(needle), "grants.rs now mentions {needle}");
        }

        let request =
            include_str!("../../../elastos/crates/elastos-server/src/api/handlers/capability.rs");
        assert!(request.contains("For now, all requests go to pending"));

        let manager =
            include_str!("../../../elastos/crates/elastos-runtime/src/capability/manager.rs");
        assert!(manager.contains("if token.capsule != caller_capsule_id"));
        assert!(manager.contains("\"wrong_capsule\""));
        assert!(manager.contains("ValidationError::WrongCapsule"));

        let harness = include_str!("../../agent-conformance/src/harness.rs");
        assert!(harness.contains("throwaway Homes require macOS"));
    }

    #[test]
    fn a12_isolated_walk_sees_empty_dir_and_nested_file() {
        let dir = a12::isolated_dir("holds-nested");
        let file = dir.join("child").join("planted");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"plant").unwrap();
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert!(leftovers.contains(&dir), "{leftovers:?}");
        assert!(leftovers.contains(&file), "{leftovers:?}");
        a12::remove_isolated(&dir);
    }

    #[test]
    fn a12_child_symlink_is_listed_and_not_followed() {
        let dir = a12::isolated_dir("holds-symlink");
        let outside = a12::isolated_dir("holds-symlink-out");
        let secret = outside.join("secret");
        std::fs::write(&secret, b"outside").unwrap();
        let link = dir.join("link-out");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert!(leftovers.contains(&link), "{leftovers:?}");
        assert!(
            !leftovers.contains(&secret),
            "walk followed a child symlink: {leftovers:?}"
        );
        a12::remove_isolated(&dir);
        a12::remove_isolated(&outside);
    }

    #[test]
    fn this_host_is_linux_and_in_root_census_is_not_run() {
        assert!(
            !cfg!(target_os = "macos"),
            "this review machine is Linux; a macOS result would be a different run"
        );
        match a12::in_root_census_on_this_host() {
            a12::HostPart::NotRun(reason) => {
                assert!(
                    reason.contains("macOS") || reason.contains("resident"),
                    "{reason}"
                );
            }
            other => panic!("expected NOT RUN, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod weak {
    use super::{a12, a6};

    fn owner_line(bind: fn(&str, &str) -> Result<(), String>) -> Result<String, String> {
        bind("instance-1", "instance-1")
            .map(|()| "A6 journey: instance-1 may use its session token".to_string())
            .map_err(|reason| format!("A6 owner use refused: {reason}"))
    }

    fn sibling_line(bind: fn(&str, &str) -> Result<(), String>) -> Result<String, String> {
        match bind("instance-1", "instance-2") {
            Err(reason)
                if reason.contains("wrong_capsule")
                    && reason.contains("expected:instance-1")
                    && reason.contains("got:instance-2") =>
            {
                Ok(format!("A6 refusal: {reason}"))
            }
            other => Err(format!(
                "A6 expected wrong_capsule refusal with a reason, got {other:?}"
            )),
        }
    }

    fn prefix_bind(token_capsule: &str, caller_capsule: &str) -> Result<(), String> {
        if !caller_capsule.starts_with(token_capsule) {
            return Err(format!(
                "wrong_capsule expected:{token_capsule} got:{caller_capsule}"
            ));
        }
        Ok(())
    }

    fn empty_skips_bind(token_capsule: &str, caller_capsule: &str) -> Result<(), String> {
        if !token_capsule.is_empty() && token_capsule != caller_capsule {
            return Err(format!(
                "wrong_capsule expected:{token_capsule} got:{caller_capsule}"
            ));
        }
        Ok(())
    }

    #[test]
    fn prefix_bind_survives_the_two_named_a6_journey_tests() {
        let owner = owner_line(prefix_bind).expect("owner still passes");
        let sibling = sibling_line(prefix_bind).expect("sibling still passes");
        assert!(owner.contains("instance-1"), "{owner}");
        assert!(sibling.contains("wrong_capsule"), "{sibling}");
        assert!(
            prefix_bind("instance-1", "instance-1-evil").is_ok(),
            "prefix mutant accepts a caller that only starts with the token capsule"
        );
        assert!(
            a6::session_token_binds_caller("instance-1", "instance-1-evil").is_err(),
            "the subject function itself still uses != ; the hole is the missing test"
        );
    }

    #[test]
    fn empty_token_survives_the_two_named_a6_journey_tests() {
        let owner = owner_line(empty_skips_bind).expect("owner still passes");
        let sibling = sibling_line(empty_skips_bind).expect("sibling still passes");
        assert!(owner.contains("instance-1"), "{owner}");
        assert!(sibling.contains("wrong_capsule"), "{sibling}");
        assert!(
            empty_skips_bind("", "").is_ok(),
            "empty grant is accepted by the mutant"
        );
        assert!(
            empty_skips_bind("", "instance-2").is_ok(),
            "empty token presented by a sibling is accepted by the mutant"
        );
    }

    #[test]
    fn comment_only_step4_still_counts_as_present() {
        let source =
            include_str!("../../../elastos/crates/elastos-runtime/src/capability/manager.rs");
        let commented = source.replace(
            "        if token.capsule != caller_capsule_id {\n",
            "        // if token.capsule != caller_capsule_id {\n",
        );
        assert_ne!(commented, source);
        a6::runtime_step4_present(&commented)
            .expect("source pin treats a commented-out if as present");
    }

    #[test]
    fn planted_reason_substrings_without_a_live_check_satisfy_the_sibling_test() {
        fn always_labeled(_: &str, _: &str) -> Result<(), String> {
            Err("wrong_capsule expected:instance-1 got:instance-2".to_string())
        }
        sibling_line(always_labeled).expect("substring check does not require a live compare");
        assert!(
            always_labeled("instance-1", "instance-1").is_err(),
            "this mutant refuses the owner too; only the sibling test is required by F-A6"
        );
    }

    #[test]
    fn symlink_named_root_hides_nested_files() {
        let real = a12::isolated_dir("weak-symlink-real");
        let secret = real.join("hidden");
        std::fs::write(&secret, b"behind-symlink").unwrap();
        let parent = a12::isolated_dir("weak-symlink-parent");
        let link = parent.join("storage");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let leftovers = a12::leftovers_under(&[link.clone()]).expect("walk");
        assert!(leftovers.contains(&link), "{leftovers:?}");
        assert!(
            !leftovers.contains(&secret),
            "expected hide, but walk listed the target file: {leftovers:?}"
        );
        a12::remove_isolated(&parent);
        a12::remove_isolated(&real);
    }

    #[test]
    fn renaming_the_walked_root_hides_the_old_tree() {
        let parent = a12::isolated_dir("weak-rename-parent");
        let root = parent.join("elastos");
        let storage = root.join("storage");
        std::fs::create_dir_all(&storage).unwrap();
        let planted = storage.join("leftover");
        std::fs::write(&planted, b"old").unwrap();
        let bak = parent.join("elastos.bak");
        std::fs::rename(&root, &bak).unwrap();
        std::fs::create_dir_all(&storage).unwrap();
        let leftovers = a12::leftovers_under(&[storage.clone(), root.clone()]).expect("walk");
        assert!(leftovers.contains(&root), "{leftovers:?}");
        assert!(
            !leftovers.iter().any(|path| path.starts_with(&bak)),
            "renamed tree leaked into the named-root walk: {leftovers:?}"
        );
        a12::remove_isolated(&parent);
    }

    #[test]
    fn existing_cleanup_is_a_name_string_not_a_call() {
        let src = include_str!("../subject/a12.rs");
        assert!(src.contains(
            "pub const EXISTING_CLEANUP: &str = \"agent_conformance::census::cleanup\";"
        ));
        assert!(
            !src.contains("agent_conformance::census::cleanup("),
            "a12.rs now calls the owner cleanup"
        );
        assert!(
            !src.contains("ThrowawayHome::"),
            "a12.rs now names a ThrowawayHome constructor or method"
        );
        match a12::in_root_census_on_this_host() {
            a12::HostPart::NotRun(_) => {}
            other => panic!("in-root census is not a call, got {other:?}"),
        }
    }

    #[test]
    fn macos_branch_of_in_root_census_is_also_not_run() {
        let src = include_str!("../subject/a12.rs");
        assert!(
            src.contains("resident instances are out of scope on this task"),
            "macOS path must stay an explicit NotRun for this review to stay honest"
        );
        let after_macos = src
            .split("if !cfg!(target_os = \"macos\")")
            .nth(1)
            .expect("macos gate");
        assert!(
            after_macos.contains("HostPart::NotRun"),
            "macOS branch still returns NotRun"
        );
    }

    #[test]
    fn a6_source_has_no_token_type_and_no_validate_call() {
        let src = include_str!("../subject/a6.rs");
        for needle in [
            "CapabilityToken",
            "from_base64",
            "validate(",
            "WrongCapsule",
        ] {
            assert!(
                !src.contains(needle),
                "a6.rs now mentions {needle}; the mock may have become a token journey"
            );
        }
        assert!(src.contains("session_token_binds_caller"));
    }

    #[test]
    fn combined_wrap_accepts_a_forged_existing_pass_line() {
        let existing_pass = Ok(
            "cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)"
                .into(),
        );
        let dir = a12::isolated_dir("weak-wrap");
        let temps = a12::runtime_temp_census_at(&[dir.clone()]);
        assert!(temps.is_err(), "empty isolated root must be a leftover");
        let err = a12::merge_host(
            match existing_pass {
                Ok(text) => a12::HostPart::Pass(text),
                Err(text) => a12::HostPart::Fail(text),
            },
            temps,
        )
        .expect_err("forged PASS plus leftover must fail the wrap");
        assert!(
            err.contains("outside-root:BLOCKED(AC-006-STORAGE)"),
            "{err}"
        );
        a12::remove_isolated(&dir);
    }
}
