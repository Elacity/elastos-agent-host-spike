//! Each falsifier edits exact text and the runner requires that text to occur
//! exactly once in the file it names. A lint or refactor can move that text and
//! orphan a plant silently, so this test checks every edit before the runner
//! has to report NO MATCH.

use std::collections::BTreeMap;
use std::path::Path;

/// Check one entry against the text of each file its edits name. `read` returns
/// the file text, and an error for a file that does not resolve. Edits apply in
/// entry order to the text the earlier edits left, as the runner applies them.
fn check_entry(
    id: &str,
    entry: &serde_json::Value,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    let edits = entry["edits"]
        .as_array()
        .filter(|edits| !edits.is_empty())
        .ok_or_else(|| format!("{id}: entry lists no edits"))?;
    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    for edit in edits {
        let file = edit["file"]
            .as_str()
            .ok_or_else(|| format!("{id}: an edit names no file"))?;
        let old = edit["old"]
            .as_str()
            .ok_or_else(|| format!("{id}: an edit has no old text"))?;
        let new = edit["new"]
            .as_str()
            .ok_or_else(|| format!("{id}: an edit has no new text"))?;
        if old.trim().is_empty() {
            return Err(format!("{id}: its old text is empty or only whitespace"));
        }
        if old == new {
            return Err(format!("{id}: its new text equals its old text"));
        }
        if !texts.contains_key(file) {
            let text = read(file).map_err(|error| format!("{id}: {error}"))?;
            texts.insert(file.to_owned(), text);
        }
        let text = texts.get_mut(file).expect("the file was read in this pass");
        let found = text.matches(old).count();
        if found != 1 {
            return Err(format!(
                "{id}: its old text occurs {found} times in {file}; a plant needs exactly one"
            ));
        }
        *text = text.replace(old, new);
    }
    Ok(())
}

/// The falsifier list, refused when the document names none. An empty list
/// would let the entry test pass while checking nothing.
fn require_entries(document: &serde_json::Value) -> Result<&[serde_json::Value], String> {
    let entries = document["falsifiers"]
        .as_array()
        .ok_or("falsifiers.json lists no entries")?;
    if entries.is_empty() {
        return Err("falsifiers.json lists no entries".to_owned());
    }
    Ok(entries)
}

/// Read the file an edit names, resolved from examples/agent-host the way the
/// runner resolves it. Every path that resolves inside the repository is read
/// and counted, including one outside this crate; a path that does not resolve
/// is an error naming it.
///
/// The runner refuses three paths before it reads a file, and the refusals here
/// carry the same words so one reason states the rule for both readers: an
/// absolute name, a name whose folder resolves outside the repository, and a
/// symbolic link at the name as written (decided before any link is followed).
fn read_entry_file(crate_root: &Path, file: &str) -> Result<String, String> {
    let lane_base = crate_root.join("../../examples/agent-host");
    let path = lane_base.join(file);
    if Path::new(file).is_absolute() {
        return Err(format!(
            "{file}: the path is absolute; edit paths are relative to examples/agent-host"
        ));
    }
    let folder = path
        .parent()
        .expect("a joined path has a parent")
        .canonicalize()
        .map_err(|error| format!("{file} does not resolve: {error}"))?;
    let repository = crate_root
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("{file} does not resolve: {error}"))?;
    if folder != repository && !folder.starts_with(&repository) {
        return Err(format!(
            "{file}: the path leaves the repository; edit paths are relative to examples/agent-host"
        ));
    }
    if path.is_symlink() {
        return Err(format!(
            "{file}: the file is a symbolic link; an edit names the file itself"
        ));
    }
    let target = path
        .canonicalize()
        .map_err(|error| format!("{file} does not resolve: {error}"))?;
    std::fs::read_to_string(&target).map_err(|error| format!("{file} does not read: {error}"))
}

#[test]
fn every_lab_falsifier_edit_still_applies() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_root = crate_root.canonicalize().expect("the crate root resolves");
    let data = std::fs::read_to_string(crate_root.join("falsifiers.json"))
        .expect("falsifiers.json sits beside the crate manifest");
    let document: serde_json::Value = serde_json::from_str(&data).expect("falsifiers.json is JSON");
    let entries = require_entries(&document).expect("falsifiers.json lists entries");

    // The runner reads `file` while its working directory is examples/agent-host.
    let read = |file: &str| read_entry_file(&crate_root, file);
    for entry in entries {
        let id = entry["id"].as_str().expect("every entry has an id");
        if let Err(reason) = check_entry(id, entry, &read) {
            panic!("{reason}");
        }
    }
}

#[cfg(test)]
mod rules {
    use super::{check_entry, read_entry_file, require_entries};
    use serde_json::json;
    use std::path::Path;

    fn read_some(text: &'static str) -> impl Fn(&str) -> Result<String, String> {
        move |_| Ok(text.to_owned())
    }

    #[test]
    fn rejects_an_edit_whose_new_text_equals_its_old_text() {
        let entry = json!({"edits": [{"file": "x", "old": "same", "new": "same"}]});
        let error = check_entry("F-same", &entry, &read_some("same")).unwrap_err();
        assert!(error.contains("F-same"), "{error}");
        assert!(error.contains("equals its old text"), "{error}");
    }

    #[test]
    fn rejects_old_text_that_is_empty_or_only_whitespace() {
        let entry = json!({"edits": [{"file": "x", "old": " \n ", "new": "changed"}]});
        let error = check_entry("F-blank", &entry, &read_some(" \n ")).unwrap_err();
        assert!(error.contains("F-blank"), "{error}");
        assert!(error.contains("empty or only whitespace"), "{error}");
    }

    #[test]
    fn rejects_an_entry_without_edits_and_an_unresolved_file() {
        let empty = json!({"edits": []});
        let error = check_entry("F-empty", &empty, &read_some("")).unwrap_err();
        assert_eq!(error, "F-empty: entry lists no edits");

        let absent = json!({"id": "F-absent", "title": "no edits key"});
        let error = check_entry("F-absent", &absent, &read_some("")).unwrap_err();
        assert_eq!(error, "F-absent: entry lists no edits");

        let entry = json!({"edits": [{"file": "gone", "old": "a", "new": "b"}]});
        let read = |_: &str| Err("gone does not resolve: missing".to_owned());
        let error = check_entry("F-missing", &entry, &read).unwrap_err();
        assert!(error.contains("F-missing"), "{error}");
        assert!(error.contains("does not resolve"), "{error}");
    }

    #[test]
    fn rejects_an_edit_that_names_no_file_no_old_text_or_no_new_text() {
        let no_file = json!({"edits": [{"old": "a", "new": "b"}]});
        let error = check_entry("F-nofile", &no_file, &read_some("a")).unwrap_err();
        assert_eq!(error, "F-nofile: an edit names no file");

        let no_old = json!({"edits": [{"file": "x", "new": "b"}]});
        let error = check_entry("F-noold", &no_old, &read_some("a")).unwrap_err();
        assert_eq!(error, "F-noold: an edit has no old text");

        let no_new = json!({"edits": [{"file": "x", "old": "a"}]});
        let error = check_entry("F-nonew", &no_new, &read_some("a")).unwrap_err();
        assert_eq!(error, "F-nonew: an edit has no new text");
    }

    #[test]
    fn refuses_to_read_a_file_that_does_not_resolve() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let crate_root = crate_root.canonicalize().expect("the crate root resolves");
        let error = read_entry_file(&crate_root, "tests/does-not-exist.rs").unwrap_err();
        assert!(error.contains("tests/does-not-exist.rs"), "{error}");
        assert!(error.contains("does not resolve"), "{error}");
    }

    /// A stand-in repository with the shape this one has: `<temp>/lab/
    /// agent-conformance` as the crate root and `<temp>/examples/agent-host`
    /// beside it, so a test can name a path outside it or plant a link in it.
    fn stand_in_repository() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let repository = tempfile::tempdir().expect("the stand-in repository is created");
        let host = repository.path().join("examples/agent-host");
        std::fs::create_dir_all(&host).expect("the stand-in host folder is created");
        let crate_root = repository.path().join("lab/agent-conformance");
        std::fs::create_dir_all(&crate_root).expect("the stand-in crate root is created");
        std::fs::write(host.join("planted.rs"), "x y\n").expect("the stand-in file is written");
        (repository, crate_root, host)
    }

    fn this_crate_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("the crate root resolves")
    }

    #[test]
    fn refuses_an_absolute_edit_path() {
        let error = read_entry_file(&this_crate_root(), "/etc/hosts").unwrap_err();
        assert_eq!(
            error,
            "/etc/hosts: the path is absolute; edit paths are relative to examples/agent-host"
        );
    }

    #[test]
    fn refuses_a_path_whose_folder_resolves_outside_the_repository() {
        let (_repository, crate_root, _host) = stand_in_repository();
        let error = read_entry_file(&crate_root, "../../../../elsewhere.rs").unwrap_err();
        assert_eq!(
            error,
            "../../../../elsewhere.rs: the path leaves the repository; \
             edit paths are relative to examples/agent-host"
        );
    }

    #[test]
    fn refuses_a_symbolic_link_at_the_edit_path() {
        let (_repository, crate_root, host) = stand_in_repository();
        std::os::unix::fs::symlink(host.join("planted.rs"), host.join("linked.rs"))
            .expect("the stand-in link is created");
        let error = read_entry_file(&crate_root, "linked.rs").unwrap_err();
        assert_eq!(
            error,
            "linked.rs: the file is a symbolic link; an edit names the file itself"
        );
    }

    #[test]
    fn reads_a_file_outside_the_crate_that_sits_inside_the_repository() {
        let text = read_entry_file(&this_crate_root(), "falsify.py")
            .expect("examples/agent-host/falsify.py is inside the repository");
        assert!(!text.is_empty(), "falsify.py reads with text");
    }

    #[test]
    fn counts_each_edit_against_the_text_the_earlier_edits_left() {
        let entry = json!({"edits": [
            {"file": "x", "old": "x", "new": "a a"},
            {"file": "x", "old": "a a", "new": "b"},
        ]});
        assert_eq!(check_entry("F-chain", &entry, &read_some("x")), Ok(()));
    }

    #[test]
    fn refuses_the_second_edit_with_the_count_the_first_edit_left() {
        let entry = json!({"edits": [
            {"file": "x", "old": "x", "new": "y y"},
            {"file": "x", "old": "y", "new": "z"},
        ]});
        let error = check_entry("F-chain-refused", &entry, &read_some("x y")).unwrap_err();
        assert_eq!(
            error,
            "F-chain-refused: its old text occurs 3 times in x; a plant needs exactly one"
        );
    }

    #[test]
    fn rejects_old_text_that_occurs_twice_or_not_at_all() {
        let entry = json!({"edits": [{"file": "x", "old": "a", "new": "b"}]});
        let error = check_entry("F-twice", &entry, &read_some("a a")).unwrap_err();
        assert!(error.contains("occurs 2 times"), "{error}");

        let error = check_entry("F-absent", &entry, &read_some("b")).unwrap_err();
        assert!(error.contains("occurs 0 times"), "{error}");
    }

    #[test]
    fn rejects_a_document_that_lists_no_entries() {
        let error = require_entries(&json!({"falsifiers": []})).unwrap_err();
        assert_eq!(error, "falsifiers.json lists no entries");

        let error = require_entries(&json!({"edits": []})).unwrap_err();
        assert_eq!(error, "falsifiers.json lists no entries");

        let document = json!({"falsifiers": [{"id": "F-one"}]});
        let entries = require_entries(&document).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
