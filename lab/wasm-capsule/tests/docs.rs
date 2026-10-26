//! Task 019: the lane's README states the falsifier total that
//! `falsifiers.json` holds (PRINCIPLES P12). README's "## Falsifiers" opens
//! with the one sentence "`falsifiers.json` holds N planted bugs"; this test
//! counts the entries of the file's `"falsifiers"` list and requires that N.
//!
//! Task 023: README's "## Falsifiers" is the one place for evidence labels and
//! counts (P10, P12). `falsifiers.json`'s `"about"` text only says what each
//! falsifier plants, states no evidence status and points to that section.

use std::fs;
use std::path::Path;

/// The words before and after the total in README's summary sentence.
const TOTAL_BEFORE: &str = "`falsifiers.json` holds ";
const TOTAL_AFTER: &str = " planted bugs";

/// Words that state an evidence status, which only README's "## Falsifiers"
/// may hold. Each is matched as a whole word, ignoring case.
const EVIDENCE_WORDS: [&str; 5] = ["pending", "hand-proven", "runner-caught", "R1", "R2"];

/// The lane file `name`, as text.
fn lane_file(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Each N that `text` states as "`falsifiers.json` holds N planted bugs", in
/// order.
fn stated_totals(text: &str) -> Vec<usize> {
    text.match_indices(TOTAL_BEFORE)
        .filter_map(|(at, _)| {
            let rest = &text[at + TOTAL_BEFORE.len()..];
            let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if digits == 0 || !rest[digits..].starts_with(TOTAL_AFTER) {
                return None;
            }
            rest[..digits].parse().ok()
        })
        .collect()
}

/// Whether `text` holds `word` as a whole word, ignoring ASCII case: no ASCII
/// letter or digit touches it on either side.
fn holds_word(text: &str, word: &str) -> bool {
    let text = text.to_ascii_lowercase();
    let word = word.to_ascii_lowercase();
    text.match_indices(&word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

#[test]
fn falsifiers_about_states_no_evidence_status() {
    let records: serde_json::Value =
        serde_json::from_str(&lane_file("falsifiers.json")).expect("parse falsifiers.json");
    let about = records["about"]
        .as_str()
        .expect("falsifiers.json has an \"about\" string");
    let found: Vec<&str> = EVIDENCE_WORDS
        .into_iter()
        .filter(|word| holds_word(about, word))
        .collect();
    assert!(
        found.is_empty(),
        "falsifiers.json \"about\" states evidence status, which README.md \"## Falsifiers\" \
         alone holds: found {found:?}"
    );
    assert!(
        about.contains("README.md"),
        "falsifiers.json \"about\" does not name README.md as the place for evidence labels"
    );
    assert!(
        about.contains("## Falsifiers"),
        "falsifiers.json \"about\" does not name the README section \"## Falsifiers\""
    );
}

#[test]
fn readme_falsifier_total_matches_falsifiers_json() {
    let records: serde_json::Value =
        serde_json::from_str(&lane_file("falsifiers.json")).expect("parse falsifiers.json");
    let held = records["falsifiers"]
        .as_array()
        .expect("falsifiers.json has a \"falsifiers\" list")
        .len();
    let stated = stated_totals(&lane_file("README.md"));
    assert_eq!(
        stated.len(),
        1,
        "README states the falsifier total {} times, not once: {stated:?}",
        stated.len()
    );
    assert_eq!(
        stated[0], held,
        "README says falsifiers.json holds {} planted bugs, but it holds {held}",
        stated[0]
    );
}
