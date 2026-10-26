//! Corrected A6 and A12 evidence. Calls Runtime `grant`/`validate` and
//! owner `census::cleanup` / `ThrowawayHome`. Does not edit those crates.

pub mod a12;
pub mod a6;
pub mod existing;

#[cfg(test)]
mod plant;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn a6_owner_may_use_own_session_token() {
        let line = a6::owner_may_use_own_token().expect("A6 owner journey");
        assert!(line.contains("instance-1"), "{line}");
        println!("{line}");
    }

    #[test]
    fn a6_sibling_presenting_owner_token_is_refused() {
        let line = a6::sibling_presenting_owner_token_is_refused().expect("A6 sibling refusal");
        assert!(
            line.contains("WrongCapsule")
                && line.contains("expected:instance-1")
                && line.contains("got:instance-2"),
            "{line}"
        );
        println!("{line}");
    }

    #[test]
    fn a6_prefix_capsule_id_is_refused() {
        let line = a6::prefix_capsule_id_is_refused().expect("A6 exact-match capsule id");
        println!("{line}");
    }

    #[test]
    fn a6_empty_token_capsule_is_refused() {
        let line = a6::empty_token_capsule_is_refused().expect("A6 empty token");
        println!("{line}");
    }

    #[test]
    fn a6_sibling_other_resource_token_is_wrong_capsule() {
        let line =
            a6::sibling_other_resource_token_is_wrong_capsule().expect("A6 other-resource sibling");
        println!("{line}");
    }

    #[test]
    fn a6_sibling_other_action_token_is_wrong_capsule() {
        let line =
            a6::sibling_other_action_token_is_wrong_capsule().expect("A6 other-action sibling");
        println!("{line}");
    }

    #[test]
    fn a6_owner_other_resource_is_wrong_resource() {
        let line = a6::owner_other_resource_is_wrong_resource().expect("A6 owner WrongResource");
        println!("{line}");
    }

    #[test]
    fn a6_expired_token_is_refused() {
        let line = a6::expired_token_is_refused().expect("A6 expired");
        println!("{line}");
    }

    #[test]
    fn a6_revoked_token_is_refused() {
        let line = a6::revoked_token_is_refused().expect("A6 revoked");
        println!("{line}");
    }

    #[test]
    fn a6_tampered_base64_is_refused() {
        let line = a6::tampered_base64_is_refused().expect("A6 tampered");
        println!("{line}");
    }

    #[test]
    fn a6_case_variant_capsule_id_is_refused() {
        let line = a6::case_variant_capsule_id_is_refused().expect("A6 case");
        println!("{line}");
    }

    #[test]
    fn a6_zero_width_capsule_id_is_refused() {
        let line = a6::zero_width_capsule_id_is_refused().expect("A6 zwsp");
        println!("{line}");
    }

    #[test]
    fn a6_resident_two_instances_is_blocked() {
        match a6::resident_two_instance_token_journey() {
            a6::JourneyStatus::Blocked { ask, reason } => {
                assert_eq!(ask, a6::RA_6, "{reason}");
                assert!(reason.contains("resident capsule instances"), "{reason}");
                println!("BLOCKED ({ask}): {reason}");
            }
            a6::JourneyStatus::Pass(line) => {
                panic!("resident two-instance journey must not PASS until RA-6: {line}")
            }
            a6::JourneyStatus::Fail(line) => {
                panic!("resident two-instance journey must be BLOCKED, not FAIL: {line}")
            }
        }
    }

    #[test]
    fn a6_empty_resident_pair_cannot_pass() {
        match a6::status_after_host_ok(a6::ResidentPair) {
            a6::JourneyStatus::Fail(reason) => {
                assert!(
                    reason.contains("empty ResidentPair") || reason.contains("stub"),
                    "{reason}"
                );
                println!("empty ResidentPair FAIL: {reason}");
            }
            other => panic!("Ok(empty ResidentPair) must FAIL, got {other:?}"),
        }
    }

    #[test]
    fn a6_does_not_claim_resident_instances() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a6.rs"));
        let findings = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/FINDINGS.md"));
        let ask = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/RA-6.md"));
        assert!(
            source.contains("not two resident capsule instances"),
            "a6.rs dropped the resident-instance disclaimer"
        );
        assert!(
            findings.contains("not two independent resident capsule instances")
                || findings.contains("never PASS until RA-6"),
            "FINDINGS.md dropped the resident-instance disclaimer"
        );
        assert!(
            ask.contains("RA-6") && ask.contains("two resident capsule instances"),
            "RA-6.md must name the Runtime ask"
        );
        println!("A6 does not claim two resident instances; RA-6 is the Runtime ask");
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
        let isolated = a12::isolated_dir("list-roots");
        a12::with_tmp_root(&isolated, || {
            let roots = a12::runtime_owned_temp_roots().expect("guarded roots");
            let storage = a12::storage_root().expect("storage");
            let tmp = a12::elastos_tmp_root().expect("tmp");
            assert!(roots.iter().any(|root| root == &storage), "{roots:?}");
            assert!(roots.iter().any(|root| root == &tmp), "{roots:?}");
            println!("A12 roots: {roots:?}");
        });
        a12::remove_isolated(&isolated);
    }

    #[test]
    fn a12_unset_tmp_root_is_refused() {
        let _lock = a12::lock_real_root();
        let previous = std::env::var_os("ELASTOS_TMP_ROOT");
        std::env::remove_var("ELASTOS_TMP_ROOT");
        let err = a12::elastos_tmp_root().expect_err("unset must be refused");
        match previous {
            Some(value) => std::env::set_var("ELASTOS_TMP_ROOT", value),
            None => std::env::remove_var("ELASTOS_TMP_ROOT"),
        }
        assert!(err.contains("unset"), "{err}");
        assert_ne!(
            a12::live_runtime_tmp_root(),
            std::path::PathBuf::from(""),
            "live Runtime temp is still /tmp/elastos as a census name only"
        );
        println!("A12 unset ELASTOS_TMP_ROOT refused: {err}");
    }

    #[test]
    fn a12_slash_tmp_root_is_refused() {
        a12::with_tmp_root(Path::new("/"), || {
            let err = a12::elastos_tmp_root().expect_err("slash must be refused");
            assert!(err.contains("refuses /"), "{err}");
            println!("A12 ELASTOS_TMP_ROOT=/ refused: {err}");
        });
    }

    #[test]
    fn a12_empty_tmp_root_is_refused() {
        let err = a12::check_tmp_root(Path::new("")).expect_err("empty");
        assert!(err.contains("empty"), "{err}");
        println!("A12 empty ELASTOS_TMP_ROOT refused: {err}");
    }

    #[test]
    fn a12_home_and_live_home_tmp_root_are_refused() {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                let err = a12::check_tmp_root(Path::new(&home)).expect_err("HOME");
                assert!(err.contains("$HOME"), "{err}");
                let mac_live = Path::new(&home).join("Library/Application Support/elastos");
                let err = a12::check_tmp_root(&mac_live).expect_err("mac live Home");
                assert!(err.contains("live Home"), "{err}");
                let linux_live = Path::new(&home).join(".local/share/elastos");
                let err = a12::check_tmp_root(&linux_live).expect_err("linux live Home");
                assert!(err.contains("live Home"), "{err}");
            }
        }
        let relative = Path::new("relative-tmp");
        let err = a12::check_tmp_root(relative).expect_err("relative");
        assert!(err.contains("absolute"), "{err}");
        println!("A12 HOME, live Home, and relative ELASTOS_TMP_ROOT refused");
    }

    #[test]
    fn a12_isolation_parent_tmp_root_is_refused() {
        let iso = a12::isolation_root();
        let escaped = iso.join("..");
        let err = a12::check_tmp_root(&escaped).expect_err("isolation/..");
        assert!(err.contains("refuses '..' component"), "{err}");
        println!("A12 ELASTOS_TMP_ROOT=$ISOLATION/.. refused: {err}");
    }

    #[test]
    fn a12_nested_dotdot_tmp_root_is_refused() {
        let iso = a12::isolation_root();
        let escaped = iso.join("hold").join("..").join("..");
        let err = a12::check_tmp_root(&escaped).expect_err("hold/../..");
        assert!(err.contains("refuses '..' component"), "{err}");
        println!("A12 ELASTOS_TMP_ROOT=$ISOLATION/hold/../.. refused: {err}");
    }

    #[test]
    fn a12_symlink_to_live_home_tmp_root_is_refused() {
        let iso = a12::isolation_root();
        let pid = std::process::id();
        let fake_live = std::env::temp_dir().join(format!("a12-fake-live-{pid}"));
        let _ = fs::remove_dir_all(&fake_live);
        fs::create_dir_all(fake_live.join(".local/share/elastos")).unwrap();
        let link = iso.join(format!("live-via-symlink-{pid}"));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&fake_live, &link).unwrap();
        let err = a12::check_tmp_root(&link).expect_err("symlink to live Home");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&fake_live);
        assert!(err.contains("refuses symlink"), "{err}");
        println!("A12 ELASTOS_TMP_ROOT symlink to live Home refused: {err}");
    }

    #[test]
    fn a12_clean_isolated_root_passes() {
        let dir = a12::isolated_dir("clean-pass");
        let missing = dir.join("does-not-exist");
        let line = a12::runtime_temp_census_at(&[missing]).expect("clean isolated root");
        assert!(line.contains("PASS leftovers:0"), "{line}");
        a12::remove_isolated(&dir);
        println!("{line}");
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
        let leftover = a12::create_runtime_storage_leftover(&dir).expect("create storage");
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert!(leftovers.contains(&leftover), "{leftovers:?}");
        a12::remove_isolated(&dir);
        println!("A12 nested leftover: {}", leftover.display());
    }

    #[test]
    fn a12_symlink_root_is_scanned_through() {
        let dir = a12::isolated_dir("symlink-root");
        let real = a12::isolated_dir("symlink-real");
        let leftover = a12::create_runtime_storage_leftover(&real).expect("create storage");
        let link = dir.join("linked-root");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let leftovers = a12::leftovers_under(&[link.clone()]).expect("walk");
        assert!(
            leftovers
                .iter()
                .any(|path| path == &leftover || path.ends_with(leftover.file_name().unwrap())),
            "census must resolve a symlink root and see the leftover: {leftovers:?}"
        );
        a12::remove_isolated(&dir);
        a12::remove_isolated(&real);
        println!("A12 symlink root scanned through to {}", leftover.display());
    }

    #[test]
    fn a12_symlink_loop_does_not_pass_as_clean() {
        let dir = a12::isolated_dir("loop");
        let link = dir.join("loop-root");
        std::os::unix::fs::symlink(&link, &link).unwrap();
        let result = a12::leftovers_under(&[link.clone()]);
        a12::remove_isolated(&dir);
        match result {
            Ok(paths) => panic!("symlink loop must not look like a clean walk: {paths:?}"),
            Err(reason) => {
                println!("A12 symlink loop refused: {reason}");
                assert!(
                    reason.contains("resolve")
                        || reason.contains("loop")
                        || reason.contains("inspect"),
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn a12_renamed_root_is_found_by_created_set() {
        let parent = a12::isolated_dir("rename-parent");
        let named = parent.join("named-root");
        fs::create_dir_all(&named).unwrap();
        let before = a12::snapshot(&parent).expect("before");
        let leftover = a12::create_runtime_storage_leftover(&named).expect("create storage");
        let bak = parent.join("named-root.bak");
        fs::rename(&named, &bak).unwrap();
        fs::create_dir_all(&named).unwrap();
        let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
        assert!(
            leftovers.iter().any(|path| path.starts_with(&bak)
                || path.ends_with(leftover.file_name().unwrap())),
            "renamed leftover must be found by created inode/path, not the old name: {leftovers:?}"
        );
        a12::remove_isolated(&parent);
        println!(
            "A12 renamed leftover found by created set under {}",
            bak.display()
        );
    }

    #[test]
    fn a12_renamed_to_unrelated_name_is_found() {
        let parent = a12::isolated_dir("unrelated");
        let named = parent.join("named-root");
        fs::create_dir_all(&named).unwrap();
        let before = a12::snapshot(&parent).expect("before");
        let leftover = a12::create_runtime_storage_leftover(&named).expect("create storage");
        let moved = parent.join("moved-away");
        fs::rename(&named, &moved).unwrap();
        fs::create_dir_all(&named).unwrap();
        let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
        assert!(
            leftovers.iter().any(|path| path.starts_with(&moved)),
            "unrelated rename moved-away must be found by created set: leftover={} leftovers={leftovers:?}",
            leftover.display()
        );
        a12::remove_isolated(&parent);
        println!(
            "A12 unrelated rename leftover found under {}",
            moved.display()
        );
    }

    #[test]
    fn a12_leftover_without_marker_is_found() {
        let parent = a12::isolated_dir("nomarker");
        let named = parent.join("named-root");
        fs::create_dir_all(&named).unwrap();
        let before = a12::snapshot(&parent).expect("before");
        let leftover = a12::create_plain_leftover(&named, "plain.txt", b"not-the-lab-marker\n")
            .expect("plain");
        let moved = parent.join("moved-away");
        fs::rename(&named, &moved).unwrap();
        let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
        let saw_plain = leftovers.iter().any(|path| {
            path.ends_with("plain.txt")
                || path == &moved.join("storage").join("plain.txt")
                || fs::read(path)
                    .ok()
                    .as_deref()
                    .is_some_and(|bytes| bytes == b"not-the-lab-marker\n")
        });
        a12::remove_isolated(&parent);
        assert!(
            saw_plain,
            "leftover without lab marker must be found by created set: leftover={} leftovers={leftovers:?}",
            leftover.display()
        );
        println!("A12 no-marker leftover found after rename to moved-away");
    }

    #[test]
    fn a12_snapshot_before_runtime_fails_if_already_wrote() {
        let dir = a12::isolated_dir("late-snap");
        let leftover = a12::create_plain_leftover(&dir, "already.txt", b"runtime wrote first\n")
            .expect("write");
        let err =
            a12::snapshot_before_runtime(&dir).expect_err("snapshot after Runtime wrote must fail");
        a12::remove_isolated(&dir);
        assert!(err.contains("before the Runtime"), "{err}");
        assert!(leftover.ends_with("already.txt"), "{}", leftover.display());
        println!("A12 late snapshot refused: {err}");
    }

    #[test]
    fn a12_inode_reuse_same_path_is_found() {
        let parent = a12::isolated_dir("inode-reuse");
        let path = parent.join("slot.txt");
        fs::write(&path, b"first\n").unwrap();
        #[cfg(unix)]
        let before_ino = {
            use std::os::unix::fs::MetadataExt;
            fs::symlink_metadata(&path).unwrap().ino()
        };
        let before = a12::snapshot(&parent).expect("before");
        fs::remove_file(&path).unwrap();
        let mut reused = false;
        for i in 0..300 {
            fs::write(&path, format!("second-{i}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if fs::symlink_metadata(&path).unwrap().ino() == before_ino {
                    reused = true;
                    break;
                }
            }
            fs::remove_file(&path).unwrap();
        }
        if !path.exists() {
            fs::write(&path, b"second-final\n").unwrap();
        }
        let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
        a12::remove_isolated(&parent);
        assert!(
            reused,
            "same-path inode reuse did not happen; identity check would not be decisive"
        );
        assert!(
            leftovers.iter().any(|p| p == &path),
            "same-path delete+recreate must be found even if the inode is reused: {leftovers:?}"
        );
        println!("A12 inode-reuse leftover found at {}", path.display());
    }

    #[test]
    fn a12_run_window_watches_tmpdir_xdg_library() {
        let _lock = a12::lock_real_root();
        let pid = std::process::id();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let sandbox = a12::isolation_root().join(format!("run-window-home-{pid}-{stamp}"));
        let xdg_cache = sandbox.join("xdg-cache");
        let xdg_data = sandbox.join("xdg-data");
        let xdg_state = sandbox.join("xdg-state");
        let xdg_runtime = sandbox.join("xdg-runtime");
        let lib_cache = sandbox.join("Library/Caches");
        let lib_support = sandbox.join("Library/Application Support");
        for dir in [
            &xdg_cache,
            &xdg_data,
            &xdg_state,
            &xdg_runtime,
            &lib_cache,
            &lib_support,
        ] {
            fs::create_dir_all(dir).unwrap();
        }
        let prev_home = std::env::var_os("HOME");
        let prev_cache = std::env::var_os("XDG_CACHE_HOME");
        let prev_data = std::env::var_os("XDG_DATA_HOME");
        let prev_state = std::env::var_os("XDG_STATE_HOME");
        let prev_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("HOME", &sandbox);
        std::env::set_var("XDG_CACHE_HOME", &xdg_cache);
        std::env::set_var("XDG_DATA_HOME", &xdg_data);
        std::env::set_var("XDG_STATE_HOME", &xdg_state);
        std::env::set_var("XDG_RUNTIME_DIR", &xdg_runtime);
        let roots = a12::extra_watch_roots();
        assert!(roots.contains(&std::env::temp_dir()), "{roots:?}");
        assert!(roots.contains(&xdg_cache), "{roots:?}");
        assert!(roots.contains(&xdg_data), "{roots:?}");
        assert!(roots.contains(&xdg_state), "{roots:?}");
        assert!(roots.contains(&xdg_runtime), "{roots:?}");
        assert!(roots.contains(&lib_cache), "{roots:?}");
        assert!(roots.contains(&lib_support), "{roots:?}");
        let before = a12::snapshot_run_window().expect("run-window snapshot");
        let tmp_file = std::env::temp_dir().join(format!("a12-run-window-tmp-{pid}-{stamp}.txt"));
        let cache_file = xdg_cache.join("outside.txt");
        let lib_file = lib_cache.join("outside.txt");
        fs::write(&tmp_file, b"tmpdir leftover\n").unwrap();
        fs::write(&cache_file, b"xdg leftover\n").unwrap();
        fs::write(&lib_file, b"library leftover\n").unwrap();
        let leftovers = a12::leftovers_in_run_window(&before).expect("run-window leftovers");
        let _ = fs::remove_file(&tmp_file);
        restore_env("HOME", prev_home);
        restore_env("XDG_CACHE_HOME", prev_cache);
        restore_env("XDG_DATA_HOME", prev_data);
        restore_env("XDG_STATE_HOME", prev_state);
        restore_env("XDG_RUNTIME_DIR", prev_runtime);
        a12::remove_isolated(&sandbox);
        assert!(
            leftovers.iter().any(|path| path == &tmp_file),
            "run window must see $TMPDIR leftover: {leftovers:?}"
        );
        assert!(
            leftovers.iter().any(|path| path == &cache_file),
            "run window must see XDG cache leftover: {leftovers:?}"
        );
        assert!(
            leftovers.iter().any(|path| path == &lib_file),
            "run window must see Library/Caches leftover: {leftovers:?}"
        );
        println!("A12 run-window watches found TMPDIR, XDG, and Library leftovers");
    }

    fn restore_env(key: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn a12_planted_storage_file_is_caught() {
        let isolated = a12::isolated_dir("plant-storage");
        a12::with_tmp_root(&isolated, || {
            let plant = a12::StoragePlant::place().expect("plant storage");
            let err =
                a12::runtime_temp_census().expect_err("planted storage leftover must fail A12");
            assert!(err.contains(plant.path().to_str().unwrap()), "{err}");
            assert!(err.contains("runtime-temp census: FAIL"), "{err}");
            println!("A12 planted-file falsifier: {err}");
            drop(plant);
        });
        a12::remove_isolated(&isolated);
    }

    #[test]
    fn a12_elastos_tmp_root_writes_nothing_under_shared_tmp() {
        let isolated = a12::isolated_dir("env-redirect");
        let shared = Path::new("/tmp/elastos");
        let existed_before = shared.exists();
        a12::with_tmp_root(&isolated, || {
            let leftover = a12::create_runtime_storage_leftover(&a12::elastos_tmp_root().unwrap())
                .expect("create storage under isolated root");
            let _ = a12::runtime_temp_census();
            let plant = a12::StoragePlant::place().expect("plant under isolated root");
            assert!(
                leftover.starts_with(&isolated),
                "leftover must stay under ELASTOS_TMP_ROOT: {}",
                leftover.display()
            );
            assert!(
                plant.path().starts_with(&isolated),
                "plant must stay under ELASTOS_TMP_ROOT: {}",
                plant.path().display()
            );
            if existed_before {
                let planted_shared = shared.join("storage").join("a6-a12-evidence-fix-planted");
                assert!(
                    !planted_shared.exists(),
                    "ELASTOS_TMP_ROOT set, but shared leftover exists: {}",
                    planted_shared.display()
                );
            } else {
                assert!(
                    !shared.exists(),
                    "ELASTOS_TMP_ROOT set, but {} was created",
                    shared.display()
                );
            }
            drop(plant);
        });
        a12::remove_isolated(&isolated);
        println!("A12 ELASTOS_TMP_ROOT kept leftovers out of /tmp/elastos");
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
    fn combined_cleanup_calls_existing_census_and_isolated_temps() {
        assert_eq!(a12::EXISTING_CLEANUP, "agent_conformance::census::cleanup");
        assert_eq!(
            a12::EXISTING_HOME,
            "agent_conformance::harness::ThrowawayHome"
        );
        let in_root = a12::in_root_census_on_this_host();
        match &in_root {
            a12::HostPart::NotRun(reason) => println!("NOT RUN: {reason}"),
            a12::HostPart::Pass(line) => println!("in-root census: {line}"),
            a12::HostPart::Fail(line) => panic!("in-root census failed: {line}"),
        }
        let isolated = a12::isolated_dir("combined");
        let leftover = a12::create_runtime_storage_leftover(&isolated).expect("create storage");
        let temps = a12::runtime_temp_census_at(&[isolated.join("storage"), isolated.clone()]);
        let err = a12::merge_host(in_root, temps)
            .expect_err("existing host part plus storage leftover must fail the wrap");
        assert!(err.contains("runtime-temp census: FAIL"), "{err}");
        assert!(
            err.contains(leftover.to_str().unwrap()) || err.contains("leftover-marker"),
            "{err}"
        );
        println!("combined wrap caught leftover after a storage-creating run: {err}");
        a12::remove_isolated(&isolated);
    }

    #[test]
    fn planted_bugs_are_caught() {
        plant::run_all();
    }
}
