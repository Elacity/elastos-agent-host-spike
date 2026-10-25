use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// The committed list records task 010's three storage-root refusals.
const EXPECTED_FALSIFIERS: usize = 3;

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

/// The committed falsifier list describes the current source exactly.
///
/// Falsifier: replace one `old` snippet with text that is not in the source,
/// or delete an entry, empty an `edits`/`tests` array, or drop a test name's
/// module prefix; this test fails on each.
#[test]
fn falsifiers_list_is_honest() {
    let path = repo_root().join("capsules/wallet-provider/falsifiers.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("falsifier list {} must be readable: {err}", path.display()));
    let doc: Value = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("falsifier list {} must be JSON: {err}", path.display()));
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
                "{id}: {file} must be repository-relative"
            );
            let source_path = root.join(file);
            let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
                panic!(
                    "{id}: edit file {} must exist and be readable: {err}",
                    source_path.display()
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
            let (module, function) = name.rsplit_once("::").unwrap_or_else(|| {
                panic!("{id}: {name} must be a fully qualified test, such as tests::<module>::<fn>")
            });
            let source_path = test_module_source(module).unwrap_or_else(|| {
                panic!("{id}: {name} must name a module of this crate, such as tests::<module>")
            });
            let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
                panic!(
                    "{id}: test module {} must be readable: {err}",
                    source_path.display()
                )
            });
            assert!(
                declares_test(&source, function),
                "{id}: {name} must be a #[test] function in {}",
                source_path.display()
            );
        }
    }
}
