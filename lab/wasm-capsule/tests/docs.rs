//! Task 019: the lane's README states the falsifier total that
//! `falsifiers.json` holds (PRINCIPLES P12). README's "## Falsifiers" opens
//! with the one sentence "`falsifiers.json` holds N planted bugs"; this test
//! counts the entries of the file's `"falsifiers"` list and requires that N.

use std::fs;
use std::path::Path;

/// The words before and after the total in README's summary sentence.
const TOTAL_BEFORE: &str = "`falsifiers.json` holds ";
const TOTAL_AFTER: &str = " planted bugs";

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
