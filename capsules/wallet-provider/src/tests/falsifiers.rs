use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The committed list records the three storage-root refusals, the two
/// profile mutations, the shared-contract mutations, the did-profile
/// shared-rule removal, the two network-allow check mutations, task 016's
/// five wallet allow-rule removals, task 020's allow-default check removal
/// and appended profile rule, task 021's canonical-token check removal
/// with the wallet rename, the did rename and the sibling-read allowance,
/// WP25, which resolves edit paths from the repository root again, task
/// 018's re-anchored WP07 on the one required list with WP26's missing
/// model profile skip, task 018's retirement of WP08 and WP10, whose
/// model-only branch is gone, task 027's WP27, which returns `Ok(false)`
/// from the sandbox gate's declared-OS branch, so a missing
/// `/usr/bin/sandbox-exec` on macOS skips and passes, and task 029's WP28,
/// which starts the provider directly when its profile file is missing, and
/// WP29, which drops the child's standard error from the one failure message,
/// and task 050's WP30, which returns `false` from the error arm of
/// `sandbox_available`, so a missing `/usr/bin/sandbox-exec` on macOS returns
/// and `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` fails,
/// and task 054's WP31, which restores the plain cut at every `;` and the
/// parenthesis count inside strings, WP32 to WP37, which disable escaping,
/// whitespace inside a string, whitespace collapse outside strings, a
/// comment's end at its newline, and the two parser refusals, and WP38, which
/// drops the newline that ends a comment and glues the tokens around it, and
/// WP39, which drops the split outside every form and glues a bare value onto
/// the next form, and WP40, which adds the separator space after an opening
/// parenthesis so a spaced allow form escapes both predicates, and task 053's
/// WP41, which starts the stderr drainer only after the wait, WP42, which makes
/// `unanswered` use a fixed `Operation not permitted` instead of the child's
/// standard error, and WP43, which returns the shared unanswered message from
/// the invalid-JSON branch, and task 055's WP44, which appends
/// `(allow file-read* (literal "/etc"))` to the did profile, WP45 to WP48,
/// which drop the removal check's `expect`, profile-path, `old` and `new`
/// conditions, and WP49 to WP53, which turn its unreadable-profile,
/// unparsable-profile, unreadable-list, not-JSON and missing-list refusals
/// into skips, and task 058's WP54, which drops the canonical-parameter
/// refusal in `start_with_profile`, so
/// `start_with_profile_refuses_a_canonical_parameter` fails, and WP55, which
/// checks the caller's whole name instead of the name before the first `=`, so
/// `start_with_profile_refuses_an_encoded_canonical_parameter` fails, and
/// task 059's WP56, which appends an unpinned `(allow process-exec)` after the
/// exec rule, so `unbound_copy_is_refused_under_profile` fails on its deadline
/// assertion, and task 060's WP57, which widens the parent read from `literal`
/// to `subpath`, so `planted_key_beneath_storage_parent_is_not_read` fails on
/// its refusal, and task 061's WP58, which drops the section check's own-id
/// rule, WP59, which drops its unregistered-id rule, WP60, which matches an id
/// as a substring instead of a whole token, WP61, which runs the section to the
/// end of the file instead of the next `## ` heading, WP62 and WP63, which
/// bypass the missing-heading and duplicate-heading refusals, WP64, which
/// skips an unreadable `CONFINEMENT.md` instead of refusing it, and task 062's
/// WP65, which appends a write grant on `STORAGE_PARENT`, so
/// `confined_outside_write_is_denied` fails on its fresh-base absence check,
/// and task 063's WP66, which restores the silent `filter_map` drop in the one
/// list reader instead of refusing an entry without a string id, so
/// `allow_rule_removal_check_rejects_bad_inputs` fails on its missing-id case,
/// and task 064's WP67, which drops the section check's character-before rule,
/// so `XDID1` names `DID1`, and WP68, which drops its character-after rule, so
/// `DID1a` names `DID1`; `falsifier_section_check_reports_missing_and_stale_ids`
/// fails on the matching case because the missing-id problem does not come,
/// and task 066's WP69, which disables the second-exec-allow refusal in
/// `check_profile_contract`, so
/// `file_profile_contract_rejects_a_second_exec_allow` fails because the
/// `/bin/sh` fixture passes, and WP70, which reads no `)` as a token boundary
/// in the exec predicate, so `process*)` escapes and the test fails on its
/// `(allow process*)` case, and task 067's WP71, which quotes every exec allow
/// after the first, so the fixture with `/bin/sh` before the shared rule quotes
/// the shared rule and the same test fails, WP72, which reads only the
/// operation names before the first filter, so the after-filter `process-exec`
/// form passes, WP73, which quotes only the first extra rule, so the
/// two-extra-rules fixture loses the second quote, WP74, which counts a token
/// inside a nested filter as an operation, so the passing
/// `(process-exec "/x")` fixture is refused, and WP75, which counts text
/// inside a string as an operation, so the passing `(allow "process-exec")`
/// fixture is refused, and task 067's second round's WP76, which drops the
/// escape flag in `profile_characters`, so the escaped-string fixture parses
/// differently and `file_profile_contract_rejects_a_second_exec_allow` and
/// `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
/// both fail, and WP77, which requires a space after `allow`, so the
/// flush-head form passes and
/// `file_profile_contract_rejects_a_second_exec_allow` fails, and task 068's
/// WP78, which renames the did operations table's cited test in
/// `capsules/did-provider/tests/confine.rs`, so
/// `every_operations_table_cites_existing_tests` fails because the cited
/// function is gone. WP79 and WP80 bypass the operations-table check's
/// unresolved-file and no-citation refusals, so
/// `operations_table_check_reports_each_missing_citation` fails. WP81 and WP82
/// bypass its absolute-path and resolved-path containment refusals, so
/// `operations_table_check_rejects_paths_outside_provider` fails. Task 069's
/// WP83 renames the wallet operations table's cited
/// `confined_outside_write_is_denied` test in `tests/confine.rs`, so
/// `every_operations_table_cites_existing_tests` fails because the cited
/// function is gone. Task 070's WP84 appends an allow rule to the did profile
/// that no declared right names, and WP85 appends the same rule to this
/// profile, so `every_did_and_wallet_allow_rule_traces_to_one_declared_right`
/// fails on each form. Task 073's WP86 renames the one platform-baseline key
/// the declared-rights check reads to the old startup-needs key, so
/// `every_did_and_wallet_allow_rule_traces_to_one_declared_right` and
/// `model_declared_rights_read_on_the_did_and_wallet_template` fail because the
/// did, wallet and model files no longer hold that key, and WP87 drops the
/// justification refusal, so `declared_rights_trace_refuses_each_bad_input`
/// fails on its missing-justification case. Task 072's WP88 appends a read and
/// write grant on `STORAGE_PARENT` to this profile, so
/// `account_operations_beneath_storage_parent_are_refused` fails because the
/// sibling `init` and the account call succeed. Task 074's WP89 drops the pin
/// table's two startup rows, so the swapped startup rules and the startup root
/// read moved under `storage` pass, WP90 drops the repeated-id refusal, WP91
/// the repeated-rule refusal and WP92 the duplicate-form refusal, so the
/// profile that holds `(allow sysctl-read)` twice reads "declared rule is not
/// an allow rule of its profile"; `declared_rights_trace_refuses_each_bad_input`
/// fails on each case. Task 075's WP93 drops the prefix refusal, so a
/// justification that names another provider passes, and WP94 drops the
/// empty-reason refusal, so a bare provider prefix passes;
/// `declared_rights_trace_refuses_each_bad_input` fails on the matching case.
/// Task 076's WP95 drops the role refusal, so a file without the lab role
/// passes, WP96 drops the provider refusal, so a file that names another
/// provider passes, and WP97 drops the platform-baseline status refusal, so a
/// baseline without its status sentence passes;
/// `declared_rights_trace_refuses_each_bad_input` fails on the matching case.
/// Task 077's WP98 replaces the missing rights-list refusal with an empty
/// list, WP99 replaces the missing platform-baseline refusal with an empty
/// map, and WP100 replaces the missing baseline rules-list refusal with an
/// empty list, so the check goes on and refuses later with other words, and
/// `declared_rights_trace_refuses_each_bad_input` fails on the matching case.
/// Task 078's WP101 replaces the missing-id refusal with an empty id, so the
/// platform-baseline entry case reads the unnamed-id refusal; WP102 replaces
/// the missing-rules-list refusal with an empty list, so the right without its
/// rules list reads "with no rules"; WP103 skips a rule that is not a string,
/// so the right with a non-string rule passes the check; and WP104 drops only
/// the pin table's `startup-sysctl` row, so the sysctl read claimed by `storage` passes the check.
/// `declared_rights_trace_refuses_each_bad_input` fails on each case. Task 089's
/// WP105 makes the lab generator `generate_profile` emit
/// `(allow file-read* (literal "/private/var/cc-confine-generated"))` after the
/// contract head, so
/// `generated_did_and_wallet_profiles_match_their_committed_oracles` fails
/// because neither declared-rights file names that rule. Task 090's WP106
/// makes the rights-list id refusal in `declared_entries` never fire, so case
/// (a) writes a profile for the unnamed right, and WP107 makes the
/// platform-baseline id refusal never fire, so case (b) writes one for the
/// unnamed baseline rule; `generator_refuses_an_unnamed_right_and_the_start_is_refused`
/// then panics at its refusal check in the did case, and the panic names
/// `did-provider` and the case. WP108 makes `write_generated_profile` create the
/// path before it calls `generate_profile`, so both cases fail the no-file
/// assertion in the did case. Task 091's WP109 makes `generate_profile` append
/// `(deny file-write* (literal "/private/var/cc-confine-generated"))` after the
/// declared rules; only the oracle comparison catches it, because the head
/// keeps its order, the contract checks read only allow forms, and the
/// comparison's sorted tail then differs, so
/// `generated_did_and_wallet_profiles_match_their_committed_oracles` fails on
/// its `differs from its committed oracle` panic. Task 093's WP110 names
/// `generate_profile` in wallet-provider's `src/main.rs`, and WP111 names it
/// in did-provider's, so `lab_generator_is_named_only_in_test_code` fails
/// because its walk reads the provider's non-test file and the refusal names
/// that path. Task 094's WP112 starts the binary bare in the stand-in's OS
/// refusal, WP113 starts it bare after a failed `init`, and WP115 ignores the
/// writer's refusal and starts under the committed `confine.sb`, so
/// `standin_launcher_refuses_a_start_it_cannot_confine` fails on cases (a),
/// (b), (e) and (d); WP114 replaces the stand-in's generated-profile start
/// with a bare start, so
/// `standin_launcher_starts_wallet_confined_under_the_generated_profile` fails
/// at its outside `init`.
const EXPECTED_FALSIFIERS: usize = 113;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|dir| dir.join("capsules/wallet-provider/src/main.rs").is_file())
        .map(Path::to_path_buf)
        .expect("wallet-provider must sit inside the repository that owns capsules/")
}

/// Resolve a test module path, such as `tests::storage_root`, to its source.
fn test_module_source(module: &str) -> Option<PathBuf> {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests");
    let mut segments = module.split("::");
    if segments.next() != Some("tests") {
        return None;
    }
    let mut source = tests_dir.join("mod.rs");
    let mut dir = tests_dir;
    for segment in segments {
        let identifier = !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !identifier {
            return None;
        }
        let file = dir.join(format!("{segment}.rs"));
        let nested = dir.join(segment).join("mod.rs");
        source = if file.is_file() {
            file
        } else if nested.is_file() {
            nested
        } else {
            return None;
        };
        dir = dir.join(segment);
    }
    Some(source)
}

/// Whether `source` declares `name` under a `#[test]` attribute.
fn declares_test(source: &str, name: &str) -> bool {
    let declaration = format!("fn {name}(");
    let mut is_test = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "#[test]" {
            is_test = true;
        } else if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("//") {
            // Attributes and comments can sit between `#[test]` and the item.
        } else if is_test && trimmed.starts_with(&declaration) {
            return true;
        } else {
            is_test = false;
        }
    }
    false
}

/// The integration test source that bare test names resolve against.
fn integration_test_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/confine.rs")
}

fn harness_tests() -> HashSet<String> {
    let executable = std::env::current_exe().expect("the test executable path must be available");
    let output = Command::new(executable)
        .args(["--list", "--format", "terse"])
        .output()
        .expect("the test executable must list its registered tests");
    assert!(
        output.status.success(),
        "the test executable --list must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("the test executable --list output must be UTF-8")
        .lines()
        .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
        .collect()
}

fn read_falsifiers_list() -> Value {
    let path = repo_root().join("capsules/wallet-provider/falsifiers.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("falsifier list {} must be readable: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("falsifier list {} must be JSON: {err}", path.display()))
}

fn assert_falsifiers_list_is_honest(doc: &Value) {
    assert!(
        doc["about"]
            .as_str()
            .is_some_and(|about| !about.trim().is_empty()),
        "the falsifier list must carry a nonempty about string"
    );
    let entries = doc["falsifiers"]
        .as_array()
        .unwrap_or_else(|| panic!("the falsifier list must carry a falsifiers array"));
    assert_eq!(
        entries.len(),
        EXPECTED_FALSIFIERS,
        "the list must record exactly {EXPECTED_FALSIFIERS} falsifiers"
    );

    let root = repo_root();
    // The one runner applies every edit relative to examples/agent-host, so
    // the list names files by that rule and this test resolves them by the
    // same rule (P10).
    let edit_base = root.join("examples/agent-host");
    let registered_tests = harness_tests();
    let mut ids: Vec<&str> = Vec::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .unwrap_or_else(|| panic!("every falsifier needs an id"));
        assert!(!id.trim().is_empty(), "every falsifier needs an id");
        assert!(!ids.contains(&id), "falsifier id {id} is used twice");
        ids.push(id);
        for field in ["title", "command"] {
            let value = entry[field]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: {field} must be a string"));
            assert!(!value.trim().is_empty(), "{id}: {field} must not be empty");
        }
        assert_eq!(
            entry["expect"].as_str(),
            Some("caught"),
            "{id}: expect must be caught"
        );

        let edits = entry["edits"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: edits must be a list"));
        assert!(!edits.is_empty(), "{id}: edits must not be empty");
        for edit in edits {
            let file = edit["file"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: every edit needs a file"));
            let old = edit["old"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: every edit needs an old snippet"));
            let new = edit["new"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: every edit needs a new snippet"));
            assert!(!old.is_empty(), "{id}: old must not be empty");
            assert!(!new.is_empty(), "{id}: new must not be empty");
            assert_ne!(old, new, "{id}: new must differ from old");
            assert!(
                !Path::new(file).is_absolute(),
                "{id}: {file} must not be absolute; \
                 edit paths are relative to examples/agent-host"
            );
            let source_path = edit_base.join(file);
            let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
                panic!(
                    "{id}: {file}: edit paths are relative to examples/agent-host; \
                     the edit file must exist and be readable: {err}"
                )
            });
            let occurrences = source.matches(old).count();
            assert_eq!(
                occurrences, 1,
                "{id}: old snippet must occur verbatim exactly once in {file}, found {occurrences}"
            );
        }

        let tests = entry["tests"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: tests must be a list"));
        assert!(!tests.is_empty(), "{id}: tests must not be empty");
        for test in tests {
            let name = test
                .as_str()
                .unwrap_or_else(|| panic!("{id}: every test name must be a string"));
            assert!(!name.is_empty(), "{id}: test names must not be empty");
            // A unit test lives under `src/tests/` and must be registered in
            // this binary. An integration test lives in `tests/confine.rs`,
            // a separate binary that cannot appear in this one's `--list`.
            let (source_path, function, unit_test) = if name.starts_with("tests::") {
                let (module, function) = name.rsplit_once("::").unwrap_or_else(|| {
                    panic!("{id}: {name} must name a function, such as tests::<module>::<fn>")
                });
                let source_path = test_module_source(module).unwrap_or_else(|| {
                    panic!("{id}: {name} must name a module of this crate, such as tests::<module>")
                });
                (source_path, function, true)
            } else if name.contains("::") {
                panic!(
                    "{id}: {name} must be a unit test under tests:: or a bare integration test name"
                );
            } else {
                (integration_test_source(), name, false)
            };
            let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
                panic!(
                    "{id}: test source {} must be readable: {err}",
                    source_path.display()
                )
            });
            assert!(
                declares_test(&source, function),
                "{id}: {name} must be a #[test] function in {}",
                source_path.display()
            );
            if unit_test {
                assert!(
                    registered_tests.contains(name),
                    "{id}: {name} must be registered in the test executable"
                );
            }
        }
    }
}

/// The committed falsifier list describes the current source and test harness.
///
/// Unit-test names must be registered in this binary; bare integration-test
/// names must be `#[test]` functions in `tests/confine.rs`, a separate binary.
///
/// Falsifier: replace one `old` snippet with text that is not in the source,
/// delete an entry, empty an `edits`/`tests` array, drop a test name's module
/// prefix, remove its module declaration, disable it with `#[cfg(any())]`, or
/// name a bare function that `tests/confine.rs` does not declare as a test;
/// this test fails on each.
#[test]
fn falsifiers_list_is_honest() {
    assert_falsifiers_list_is_honest(&read_falsifiers_list());
}

// Keep the test declaration in source while removing it from the harness.
#[cfg(any())]
#[test]
fn excluded_from_harness() {
    panic!("this fixture must remain excluded from the test harness");
}

#[test]
#[should_panic(
    expected = "WP01: tests::falsifiers::excluded_from_harness must be registered in the test executable"
)]
fn falsifiers_list_rejects_a_test_removed_from_harness() {
    let mut doc = read_falsifiers_list();
    doc["falsifiers"][0]["tests"][0] =
        Value::String("tests::falsifiers::excluded_from_harness".into());
    assert_falsifiers_list_is_honest(&doc);
}

/// A bare integration name must be a `#[test]` function in `tests/confine.rs`.
///
/// Regression: an unknown bare name, and `profile_forms`, which is a helper
/// there but not a test, must both be refused. Bypassing the integration
/// `declares_test` check makes this test fail because nothing panics.
#[test]
fn falsifiers_list_rejects_invalid_integration_test() {
    let manifest = integration_test_source();
    for selector in ["not_a_confine_test", "profile_forms"] {
        let mut doc = read_falsifiers_list();
        assert_eq!(doc["falsifiers"][3]["id"], "WP04");
        doc["falsifiers"][3]["tests"][0] = Value::String(selector.into());
        let refusal = std::panic::catch_unwind(|| assert_falsifiers_list_is_honest(&doc))
            .expect_err("the list must refuse a bare name that is not a confine #[test]");
        let expected = format!(
            "WP04: {selector} must be a #[test] function in {}",
            manifest.display()
        );
        assert_eq!(refusal.downcast_ref::<String>(), Some(&expected));
    }
}

/// The list names edit files by the runner's rule, not the repository root.
///
/// Regression: writing every edit path from the repository root must be
/// refused for WP01, the first entry, in the runner's own words.
///
/// Falsifier: resolve edits from `repo_root()` again (WP25); this test fails
/// because the WP01 refusal does not come.
#[test]
fn falsifiers_list_rejects_a_repository_relative_path() {
    let mut doc = read_falsifiers_list();
    let entries = doc["falsifiers"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("the falsifier list must carry a falsifiers array"));
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .unwrap_or_else(|| panic!("every falsifier needs an id"))
            .to_owned();
        let edits = entry["edits"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("{id}: edits must be a list"));
        for edit in edits {
            let file = edit["file"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: every edit needs a file"));
            let repository_relative = file.strip_prefix("../../").unwrap_or_else(|| {
                panic!("{id}: {file} must start with ../../ (relative to examples/agent-host)")
            });
            edit["file"] = Value::String(repository_relative.to_owned());
        }
    }
    let refusal = std::panic::catch_unwind(|| assert_falsifiers_list_is_honest(&doc))
        .expect_err("the list must refuse paths written from the repository root");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    let expected = "WP01: capsules/wallet-provider/src/main.rs: \
                    edit paths are relative to examples/agent-host";
    assert!(
        message.contains(expected),
        "the refusal must name WP01, its file and the runner's path rule; got: {message}"
    );
}
