//! Each falsifier edits exact text and the runner requires that text to occur
//! exactly once in the file it names. A lint or refactor can move that text and
//! orphan a plant silently, so this test checks every edit before the runner
//! has to report NO MATCH.

use std::path::Path;

/// Check one entry against the text of each file its edits name. `read` returns
/// `Some(text)` for a file this test owns, `None` for a file it does not, and
/// `Err` for a file that does not resolve.
fn check_entry(
    id: &str,
    entry: &serde_json::Value,
    read: &dyn Fn(&str) -> Result<Option<String>, String>,
) -> Result<(), String> {
    let edits = entry["edits"]
        .as_array()
        .filter(|edits| !edits.is_empty())
        .ok_or_else(|| format!("{id}: entry lists no edits"))?;
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
        let Some(text) = read(file).map_err(|error| format!("{id}: {error}"))? else {
            continue;
        };
        let found = text.matches(old).count();
        if found != 1 {
            return Err(format!(
                "{id}: its old text occurs {found} times in {file}; a plant needs exactly one"
            ));
        }
    }
    Ok(())
}

#[test]
fn every_lab_falsifier_edit_still_applies() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_root = crate_root.canonicalize().expect("the crate root resolves");
    let data = std::fs::read_to_string(crate_root.join("falsifiers.json"))
        .expect("falsifiers.json sits beside the crate manifest");
    let document: serde_json::Value = serde_json::from_str(&data).expect("falsifiers.json is JSON");
    let entries = document["falsifiers"]
        .as_array()
        .expect("falsifiers.json lists entries");

    // The runner reads `file` while its working directory is examples/agent-host.
    let lane_base = crate_root.join("../../examples/agent-host");
    let read = |file: &str| {
        let target = lane_base
            .join(file)
            .canonicalize()
            .map_err(|error| format!("{file} does not resolve: {error}"))?;
        if !target.starts_with(&crate_root) {
            return Ok(None);
        }
        std::fs::read_to_string(&target)
            .map(Some)
            .map_err(|error| format!("{file} does not read: {error}"))
    };
    for entry in entries {
        let id = entry["id"].as_str().expect("every entry has an id");
        if let Err(reason) = check_entry(id, entry, &read) {
            panic!("{reason}");
        }
    }
}

#[cfg(test)]
mod rules {
    use super::check_entry;
    use serde_json::json;

    fn read_some(text: &'static str) -> impl Fn(&str) -> Result<Option<String>, String> {
        move |_| Ok(Some(text.to_owned()))
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
        assert!(error.contains("F-empty"), "{error}");

        let entry = json!({"edits": [{"file": "gone", "old": "a", "new": "b"}]});
        let read = |_: &str| Err("gone does not resolve: missing".to_owned());
        let error = check_entry("F-missing", &entry, &read).unwrap_err();
        assert!(error.contains("F-missing"), "{error}");
        assert!(error.contains("does not resolve"), "{error}");
    }

    #[test]
    fn rejects_old_text_that_occurs_twice_or_not_at_all() {
        let entry = json!({"edits": [{"file": "x", "old": "a", "new": "b"}]});
        let error = check_entry("F-twice", &entry, &read_some("a a")).unwrap_err();
        assert!(error.contains("occurs 2 times"), "{error}");

        let error = check_entry("F-absent", &entry, &read_some("b")).unwrap_err();
        assert!(error.contains("occurs 0 times"), "{error}");
    }
}
