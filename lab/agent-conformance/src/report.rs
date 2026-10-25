//! Grade only Cargo's listed tests and explicit libtest result lines.

use std::collections::BTreeMap;

fn grade(result: &str) -> String {
    if result == "ok" {
        return "PASS".into();
    }
    if let Some(reason) = result.strip_prefix("ignored, blocked: ") {
        if let Some(id) = reason.split_whitespace().next() {
            return format!("BLOCKED ({id})");
        }
    }
    "FAIL".into()
}

/// A missing, repeated or unlisted result fails closed. Cargo failure is also
/// visible even if compilation or a test binary failed before reporting a row.
pub fn table(listed: &str, output: &str, cargo_ok: bool) -> (String, bool) {
    let mut rows: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for line in listed.lines() {
        if let Some(name) = line.strip_suffix(": test") {
            if rows.insert(name, Vec::new()).is_some() {
                return (
                    "test | PASS/FAIL/BLOCKED (id)\ncargo | FAIL\n".into(),
                    false,
                );
            }
        }
    }
    for line in output.lines() {
        if let Some((name, result)) = line
            .strip_prefix("test ")
            .and_then(|s| s.split_once(" ... "))
        {
            let values = rows.entry(name).or_insert_with(|| vec!["FAIL".into()]);
            values.push(grade(result));
        }
    }
    let mut text = String::from("test | PASS/FAIL/BLOCKED (id)\n");
    let mut passed = cargo_ok && !rows.is_empty();
    if !passed {
        text.push_str("cargo | FAIL\n");
    }
    for (name, values) in rows {
        let result = if values.len() == 1 {
            values[0].as_str()
        } else {
            "FAIL"
        };
        passed &= result != "FAIL";
        text.push_str(&format!("{name} | {result}\n"));
    }
    (text, passed)
}
