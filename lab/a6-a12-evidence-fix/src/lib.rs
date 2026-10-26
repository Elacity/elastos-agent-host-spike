//! Corrected A6 and A12 evidence. Reuses the agent-conformance harness
//! (import of `census` / `ThrowawayHome`, and invoke of those types) and
//! does not edit that lane.

pub mod a12;
pub mod a6;
pub mod existing;

#[cfg(test)]
mod plant;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a6_owner_may_use_own_session_token() {
        let line = a6::owner_may_use_own_token().expect("A6 owner journey");
        assert!(line.contains("instance-1"), "{line}");
        println!("{line}");
    }

    #[test]
    fn a6_sibling_presenting_owner_token_is_refused() {
        let line = a6::sibling_presenting_owner_token_is_refused().expect("A6 sibling refusal");
        assert!(line.contains("wrong_capsule"), "{line}");
        assert!(line.contains("expected:instance-1"), "{line}");
        assert!(line.contains("got:instance-2"), "{line}");
        println!("{line}");
    }

    #[test]
    fn a6_runtime_session_token_check_is_present() {
        let source = existing::runtime_validate_source();
        let line = a6::runtime_step4_present(source).expect("Runtime step 4");
        println!("{line}");
    }

    #[test]
    fn a6_absent_runtime_session_token_check_is_caught() {
        let source = existing::runtime_validate_source()
            .replace("        if token.capsule != caller_capsule_id {\n", "");
        let err = a6::runtime_step4_present(&source).expect_err("absent step 4 must be caught");
        assert!(err.contains("session-token check is absent"), "{err}");
        println!("A6 falsifier (source): {err}");
    }

    #[test]
    fn existing_a6_journeys_do_not_present_a_session_token() {
        let line = existing::a6_journeys_omit_token_presentation().expect("gap still present");
        println!("{line}");
    }

    #[test]
    fn existing_a6_request_path_sends_every_request_to_pending() {
        let line = existing::request_path_sends_every_request_to_pending().expect("pending path");
        println!("{line}");
    }

    #[test]
    fn a12_census_lists_runtime_storage() {
        let roots = a12::runtime_owned_temp_roots();
        assert!(
            roots
                .iter()
                .any(|root| root == std::path::Path::new("/tmp/elastos/storage")),
            "A12 census must name /tmp/elastos/storage: {roots:?}"
        );
        assert!(
            roots
                .iter()
                .any(|root| root == std::path::Path::new("/tmp/elastos")),
            "A12 census must name /tmp/elastos: {roots:?}"
        );
        println!("A12 roots: {roots:?}");
    }

    #[test]
    fn a12_empty_root_is_leftover() {
        let dir = a12::isolated_dir("empty-root");
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert_eq!(leftovers, vec![dir.clone()], "{leftovers:?}");
        a12::remove_isolated(&dir);
        println!("A12 empty root is leftover: {}", dir.display());
    }

    #[test]
    fn a12_isolated_walk_catches_a_nested_file() {
        let dir = a12::isolated_dir("nested");
        let file = dir.join("child").join("planted");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"plant").unwrap();
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert!(leftovers.contains(&file), "{leftovers:?}");
        a12::remove_isolated(&dir);
        println!("A12 nested leftover: {}", file.display());
    }

    #[test]
    fn a12_symlink_root_is_leftover_and_not_followed() {
        let dir = a12::isolated_dir("symlink-root");
        let outside = a12::isolated_dir("symlink-outside");
        let secret = outside.join("secret");
        std::fs::write(&secret, b"outside").unwrap();
        let link = dir.join("link-out");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert!(leftovers.contains(&link), "{leftovers:?}");
        assert!(
            !leftovers.contains(&secret),
            "census must not follow a symlink out of the root: {leftovers:?}"
        );
        a12::remove_isolated(&dir);
        a12::remove_isolated(&outside);
        println!("A12 symlink leftover without follow: {}", link.display());
    }

    #[test]
    fn a12_planted_storage_file_is_caught() {
        let plant = a12::StoragePlant::place().expect("plant /tmp/elastos/storage");
        let err = a12::runtime_temp_census().expect_err("planted storage leftover must fail A12");
        assert!(err.contains(plant.path().to_str().unwrap()), "{err}");
        assert!(err.contains("runtime-temp census: FAIL"), "{err}");
        println!("A12 planted-file falsifier: {err}");
        drop(plant);
    }

    #[test]
    fn existing_census_ignores_runtime_storage() {
        let line = existing::census_ignores_runtime_storage().expect("gap still present");
        println!("{line}");
    }

    #[test]
    fn existing_cleanup_leftover_test_plants_only_in_home_temp() {
        let line = existing::cleanup_leftover_test_plants_only_in_home_temp().expect("gap");
        println!("{line}");
    }

    #[test]
    fn existing_harness_throwaway_home_on_this_host() {
        let part = a12::in_root_census_on_this_host();
        match part {
            a12::HostPart::NotRun(reason) => {
                println!("NOT RUN: {reason}");
                assert!(
                    reason.contains("macOS") || reason.contains("resident"),
                    "{reason}"
                );
            }
            a12::HostPart::Pass(line) => println!("in-root census: {line}"),
            a12::HostPart::Fail(line) => panic!("in-root census failed: {line}"),
        }
    }

    #[test]
    fn combined_cleanup_imports_existing_census() {
        let in_root = a12::in_root_census_on_this_host();
        let temps = a12::runtime_temp_census();
        let merged = a12::merge_host(in_root, temps);
        println!("combined cleanup: {merged:?}");
        let _ = merged;
    }

    #[test]
    fn planted_bugs_are_caught() {
        plant::run_all();
    }
}
