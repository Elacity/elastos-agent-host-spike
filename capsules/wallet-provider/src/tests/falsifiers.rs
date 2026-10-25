use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The committed list records the three storage-root refusals, the two
/// profile mutations, the five shared-contract mutations, the did-profile
/// shared-rule removal, the two network-allow check mutations, task 016's
/// five wallet allow-rule removals, task 020's allow-default check removal
/// and appended profile rule, task 021's canonical-token check removal
/// with the wallet rename, the did rename and the sibling-read allowance,
/// and WP25, which resolves edit paths from the repository root again.
const EXPECTED_FALSIFIERS: usize = 25;

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
/// because the repository-relative list is accepted.
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
                panic!("{id}: {file} must name a path under examples/agent-host")
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
