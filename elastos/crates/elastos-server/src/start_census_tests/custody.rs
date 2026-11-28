//! Test-inclusive custody start census. Read source files directly: production
//! module reachability deliberately removes the very fixtures this row owns.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::{code_only, enclosing_fn, skip_braced, without_test_items};

fn sources() -> BTreeMap<String, String> {
    fn visit(root: &Path, dir: &Path, found: &mut BTreeMap<String, String>) {
        if !dir.exists() {
            return;
        }
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    fs::read_to_string(path).unwrap(),
                );
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut found = BTreeMap::new();
    for package in [
        "elastos/crates/elastos-server",
        "elastos/crates/elastos-runtime",
        "capsules/custody-provider",
    ] {
        for dir in ["src", "tests"] {
            visit(&root, &root.join(package).join(dir), &mut found);
        }
    }
    found
}

fn unfenced(sources: &BTreeMap<String, String>) -> Vec<String> {
    let mut failures = Vec::new();
    for (file, text) in sources {
        let code = code_only(text);
        let production = code_only(&without_test_items(text));
        let test_file = file.contains("/tests/")
            || file.ends_with("/tests.rs")
            || file.contains("_tests/")
            || file.ends_with("_tests.rs");
        // Every function in the two fixture files is in scope, including a
        // renamed wrapper with a generic `binary` argument.
        let fixture = file.contains("custody")
            || text.contains("CARGO_BIN_EXE_custody-provider")
            || file.ends_with("protected_content_runtime/tests.rs")
            || file.ends_with("custody_test_support.rs");
        for (start, _) in code.match_indices("fn ") {
            let Some(open) = code[start..].find('{').map(|offset| start + offset) else {
                continue;
            };
            let end = skip_braced(code.as_bytes(), open);
            let prefix_start = code[..start].rfind(['}', ';']).map_or(0, |at| at + 1);
            let prefix = &code[prefix_start..start];
            let test_attribute = prefix.contains("#[test]") || prefix.contains("#[tokio::test");
            if !fixture && !test_file && !test_attribute && production.contains(&code[start..end]) {
                continue;
            }
            let raw = &text[start..end];
            if !fixture && !raw.to_ascii_lowercase().contains("custody") {
                continue;
            }
            let body = &code[start..end];
            for needle in [
                "Command::new(",
                ".spawn()",
                ".output()",
                ".status()",
                "libc::execve(",
                "libc::fexecve(",
                "ProviderBridge::spawn",
                "ProviderBridge::attach_",
            ] {
                for (offset, _) in body.match_indices(needle) {
                    let at = start + offset;
                    if needle == "ProviderBridge::spawn"
                        && ["_path_allow(", "_custody_provision("]
                            .iter()
                            .any(|tail| code[at + needle.len()..].starts_with(tail))
                    {
                        continue;
                    }
                    // Fixture compilation is a separate start; only its exact
                    // command expression is exempt, never the whole function.
                    let statement_start = code[..at].rfind(';').map_or(start, |i| i + 1);
                    let statement_end = code[at..].find(';').map_or(end, |i| at + i);
                    let statement = &text[statement_start..statement_end];
                    if ["rustc", "/bin/sleep"]
                        .iter()
                        .any(|program| statement.contains(&format!("Command::new(\"{program}\")")))
                        && statement.matches("Command::new(").count() == 1
                    {
                        continue;
                    }
                    if needle == ".status()" {
                        let receiver = super::receiver_before(&code, at);
                        if !statement.contains("Command::")
                            && !receiver.contains("command")
                            && receiver != "cmd"
                        {
                            continue;
                        }
                    }
                    if needle.starts_with("ProviderBridge::")
                        && statement.contains("fixture_executable(&protect_binary)")
                        && raw.contains("TEST_PROTECT_PROVIDER_BIN_ENV")
                    {
                        continue;
                    }
                    failures.push(format!(
                        "{file}:{}:{}: unfenced custody start {needle}",
                        text[..at].bytes().filter(|byte| *byte == b'\n').count() + 1,
                        enclosing_fn(&code, at),
                    ));
                }
            }
        }
    }
    failures
}

pub(crate) fn assert_fenced() {
    let sources = sources();
    for required in [
        "capsules/custody-provider/tests/process.rs",
        "elastos/crates/elastos-server/src/protected_content_runtime/tests.rs",
        "elastos/crates/elastos-runtime/src/provider/custody_test_support.rs",
    ] {
        assert!(
            sources.contains_key(required),
            "missing custody source {required}"
        );
    }
    let failures = unfenced(&sources);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_custody_start_including_test_fixtures_uses_the_fence() {
    assert_fenced();
}

#[test]
fn census_rejects_unfenced_custody_in_inline_and_separate_tests() {
    for (file, text) in [
        ("capsules/custody-provider/tests/new_fixture.rs", "fn start(binary: &Path) { Command::new(binary).spawn().unwrap(); }"),
        ("elastos/crates/elastos-server/src/new_test.rs", "#[cfg(test)] mod tests { fn custody_fixture() { Command::new(binary).output().unwrap(); } }"),
        ("elastos/crates/elastos-server/src/inline.rs", "#[test] fn custody_fixture() { Command::new(binary).output().unwrap(); }"),
        ("elastos/crates/elastos-server/src/inline.rs", "const BIN: &str = env!(\"CARGO_BIN_EXE_custody-provider\"); #[test] fn start() { Command::new(BIN).spawn().unwrap(); }"),
        ("elastos/crates/elastos-server/src/inline.rs", "#[test] fn start() { Command::new(CUSTODY_BIN).spawn().unwrap(); }"),
        ("capsules/custody-provider/tests/new_fixture.rs", "fn start(binary: &Path) { ProviderBridge::spawn_confined(binary, config); }"),
        ("elastos/crates/elastos-runtime/tests/new_test.rs", "#[test] fn raw_custody_start() { command.status().unwrap(); }"),
    ] {
        assert!(!unfenced(&BTreeMap::from([(file.to_string(), text.to_string())])).is_empty());
    }
    let quoted = "fn custody_examples() { let example = \"Command::new(binary).spawn()\"; /* command.output() */ }";
    assert!(unfenced(&BTreeMap::from([(
        "example.rs".to_string(),
        quoted.to_string()
    )]))
    .is_empty());
}
