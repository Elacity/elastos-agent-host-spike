//! Task 019: the lane's README states the falsifier total that
//! `falsifiers.json` holds (PRINCIPLES P12). README's "## Falsifiers" opens
//! with the one sentence "`falsifiers.json` holds N planted bugs"; this test
//! counts the entries of the file's `"falsifiers"` list and requires that N.
//!
//! Task 023: README's "## Falsifiers" is the one place for evidence labels and
//! counts (P10, P12). `falsifiers.json`'s `"about"` text only says what each
//! falsifier plants, states no evidence status and points to that section.
//!
//! Task 026: two rulings from Rong (26 Oct), each in one exact sentence. Both
//! engines are test-only and not endorsed, and the engine choice is Anders's;
//! every mention of endorsement in README, ADOPTION and `tools/src/run.rs`
//! says "not endorsed". And task 022's hosting discovery is not the lab's
//! import path (P10, P18): README says so before its per-engine answers, and
//! ADOPTION says the same.

use std::fs;
use std::path::Path;

/// The words before and after the total in README's summary sentence.
const TOTAL_BEFORE: &str = "`falsifiers.json` holds ";
const TOTAL_AFTER: &str = " planted bugs";

/// Words that state an evidence status, which only README's "## Falsifiers"
/// may hold. Each is matched as a whole word, ignoring case.
const EVIDENCE_WORDS: [&str; 5] = ["pending", "hand-proven", "runner-caught", "R1", "R2"];

/// Rong's engine ruling, held once by README and once by ADOPTION.
const ENGINE_RULING: &str = "Both engines, wasmtime and wasmer, are test-only and not endorsed. \
                             The engine choice is Anders's.";

/// Rong's ruling on task 022's discovery, held once by README's 022 section
/// and once by ADOPTION.
const DISCOVERY_RULING: &str = "Discovery only: no engine-specific host-function route (a preload \
                                module or a CLI flag) becomes the lab's import path; granted \
                                imports stay a stand-in for the Runtime/provider contract (P10, \
                                P18).";

/// README's section for task 022.
const HOSTING_SECTION: &str = "## Granted import hosting discovery (wc-009b0)";

/// How each per-engine answer line of the 022 section starts: each engine's
/// own heading, and its line in "The answer for wc-009b".
const ENGINE_ANSWER_STARTS: [&str; 4] = ["### wasmtime", "### wasmer", "- wasmtime:", "- wasmer:"];

/// The runner's source, whose two engine doc comments carry the label.
const RUN_SOURCE: &str = "tools/src/run.rs";

/// The label both engine doc comments in `tools/src/run.rs` carry.
const ENGINE_LABEL: &str = "test-only, not endorsed";

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

/// Each line of `text` with the byte offset it starts at, without its newline.
fn lines_at(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_inclusive('\n').scan(0, |at, line| {
        let start = *at;
        *at += line.len();
        Some((start, line.trim_end_matches('\n')))
    })
}

/// The `## ` sections of `text` in order, as (heading line, section text). A
/// section runs from its heading line to the next `## ` line; the text before
/// the first heading has the heading "".
fn sections(text: &str) -> Vec<(&str, &str)> {
    let mut starts: Vec<usize> = lines_at(text)
        .filter(|(_, line)| line.starts_with("## "))
        .map(|(at, _)| at)
        .collect();
    starts.insert(0, 0);
    starts.push(text.len());
    starts
        .windows(2)
        .map(|pair| {
            let section = &text[pair[0]..pair[1]];
            let heading = section
                .lines()
                .next()
                .filter(|line| line.starts_with("## "));
            (heading.unwrap_or(""), section)
        })
        .collect()
}

/// Each line of the lane file `name` that holds "endorse" (ignoring case)
/// but not "not endorsed", as `name:line: text`.
fn unlabelled_endorsements(name: &str, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.to_ascii_lowercase();
            line.contains("endorse") && !line.contains("not endorsed")
        })
        .map(|(index, line)| format!("{name}:{}: {line}", index + 1))
        .collect()
}

/// The `///` doc lines directly above the line `item` in `source`, past any
/// attribute lines.
fn doc_above<'a>(source: &'a str, item: &str) -> Vec<&'a str> {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines
        .iter()
        .position(|line| *line == item)
        .unwrap_or_else(|| panic!("{RUN_SOURCE} has no line {item:?}"));
    lines[..at]
        .iter()
        .rev()
        .skip_while(|line| line.starts_with("#["))
        .take_while(|line| line.starts_with("///"))
        .copied()
        .collect()
}

#[test]
fn engines_are_labelled_test_only_not_endorsed() {
    for name in ["README.md", "ADOPTION.md"] {
        let held = lane_file(name).matches(ENGINE_RULING).count();
        assert_eq!(
            held, 1,
            "{name} holds the engine ruling {held} times, not once: {ENGINE_RULING:?}"
        );
    }

    let readme = lane_file("README.md");
    let (first, section) = sections(&readme)
        .into_iter()
        .find(|(_, section)| {
            let section = section.to_ascii_lowercase();
            section.contains("wasmtime") && section.contains("wasmer")
        })
        .expect("README.md has no section that names wasmtime and wasmer");
    assert!(
        section.contains(ENGINE_RULING),
        "README.md's engine ruling is not in {first:?}, the first section that names wasmtime \
         and wasmer"
    );

    let run = lane_file(RUN_SOURCE);
    assert!(
        run.lines()
            .any(|line| line.starts_with("//!") && line.contains(ENGINE_LABEL)),
        "{RUN_SOURCE}'s module doc has no line saying {ENGINE_LABEL:?}"
    );
    assert!(
        doc_above(&run, "pub enum Engine {")
            .iter()
            .any(|line| line.contains(ENGINE_LABEL)),
        "{RUN_SOURCE}'s doc comment on `pub enum Engine` does not say {ENGINE_LABEL:?}"
    );

    let unlabelled: Vec<String> = ["README.md", "ADOPTION.md", RUN_SOURCE]
        .into_iter()
        .flat_map(|name| unlabelled_endorsements(name, &lane_file(name)))
        .collect();
    assert!(
        unlabelled.is_empty(),
        "a line mentions endorsement without \"not endorsed\": {unlabelled:#?}"
    );
}

#[test]
fn hosting_discovery_is_not_the_import_path() {
    let readme = lane_file("README.md");
    let held = readme.matches(DISCOVERY_RULING).count();
    assert_eq!(
        held, 1,
        "README.md holds the discovery ruling {held} times, not once: {DISCOVERY_RULING:?}"
    );
    let (_, section) = sections(&readme)
        .into_iter()
        .find(|(heading, _)| *heading == HOSTING_SECTION)
        .unwrap_or_else(|| panic!("README.md has no section {HOSTING_SECTION:?}"));
    let ruling_at = section.find(DISCOVERY_RULING).unwrap_or_else(|| {
        panic!("README.md's section {HOSTING_SECTION:?} does not hold the discovery ruling")
    });
    let (answer_at, answer) = lines_at(section)
        .find(|(_, line)| {
            ENGINE_ANSWER_STARTS
                .iter()
                .any(|start| line.starts_with(start))
        })
        .unwrap_or_else(|| {
            panic!(
                "README.md's section {HOSTING_SECTION:?} has no per-engine answer line \
                 (a line starting with one of {ENGINE_ANSWER_STARTS:?})"
            )
        });
    assert!(
        ruling_at < answer_at,
        "README.md's discovery ruling comes after the first per-engine answer line of \
         {HOSTING_SECTION:?}: {answer:?}"
    );

    let held = lane_file("ADOPTION.md").matches(DISCOVERY_RULING).count();
    assert_eq!(
        held, 1,
        "ADOPTION.md holds the discovery ruling on one line {held} times, not once: \
         {DISCOVERY_RULING:?}"
    );
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
