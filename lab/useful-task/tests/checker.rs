use std::path::PathBuf;

use serde_json::{json, Value};
use useful_task::{judge, load_spec, sha256_hex, Schema, Verdict};

const M1: &str = "A4: Each agent completes one useful task through real Runtime resources (model via a Runtime grant, DeepSeek on the Sparks); the permitted effect succeeds (granted_effect_succeeds).";
const REASONS: [&str; 9] = [
    "task",
    "input",
    "recorded",
    "empty",
    "echo",
    "fixed-string",
    "shape",
    "duplicate",
    "mismatch",
];
const FIXED_STRINGS: [&str; 4] = ["ok", "done", "TODO", "pass"];

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn accepted(answer: &str) -> Verdict {
    Verdict::Accept {
        answer_sha256: sha256_hex(answer.trim()),
    }
}

fn refused(reason: &'static str) -> Verdict {
    Verdict::Refuse { reason }
}

fn parsed(json: &str) -> Value {
    serde_json::from_str(json).expect("test JSON parses")
}

fn refused_spec(bytes: &str, reason: &str) {
    assert_eq!(load_spec(bytes).expect_err("malformed spec"), reason);
}

fn changed_spec_refused(spec: &Value, key: &str, value: Option<Value>, reason: &str) {
    let mut changed = spec.clone();
    let object = changed.as_object_mut().unwrap();
    match value {
        Some(value) => object.insert(key.to_owned(), value),
        None => object.remove(key),
    };
    refused_spec(&changed.to_string(), reason);
}

#[test]
fn checker_accepts_recorded_answer_and_refuses_stubs() {
    let a_input = read("tasks/agent-a/input.txt");
    let a_recorded = read("tasks/agent-a/recorded.json");
    let b_input = read("tasks/agent-b/input.txt");
    let b_recorded = read("tasks/agent-b/recorded.json");

    assert_eq!(
        sha256_hex(&a_input),
        "6cce0615e268e9a905d394b4e6f1c228fef86569ef8778c006626b1a45d57f30"
    );
    assert_eq!(
        sha256_hex(&a_recorded),
        "043eec2fa4d70dafc04b87b9b594b703dc6a3f9db7d1f2baca9a2c50d44e3468"
    );
    assert_eq!(
        sha256_hex(&b_input),
        "0473bb0ead0e492638e72828a7621aad7f38cb9933045170cf13d0b8fdd7b699"
    );
    assert_eq!(
        sha256_hex(&b_recorded),
        "c72098886eb378e448bcb33a922b153a7a39f058ffaa1c5a48f80b210d2221a7"
    );

    let a_spec_bytes = read("tasks/agent-a/accept.json");
    let b_spec_bytes = read("tasks/agent-b/accept.json");
    let a_spec = load_spec(&a_spec_bytes).expect("agent-a spec parses");
    let b_spec = load_spec(&b_spec_bytes).expect("agent-b spec parses");
    refused_spec(
        "[",
        "spec is not JSON: EOF while parsing a list at line 1 column 1",
    );
    for repeated in [
        a_spec_bytes.replacen("\"m1\":", "\"m1\":\"other\",\"m1\":", 1),
        a_spec_bytes.replacen("\"m1\":", "\"\\u006d1\":\"other\",\"m1\":", 1),
        b_spec_bytes.replacen("\"task_id\":", "\"task_id\":\"other\",\"task_id\":", 1),
    ] {
        refused_spec(&repeated, "spec repeats a key");
    }
    refused_spec("null", "spec is not an object");
    for (bytes, schema_key) in [
        (read("tasks/agent-a/accept.json"), "fields"),
        (read("tasks/agent-b/accept.json"), "item_fields"),
    ] {
        let spec = parsed(&bytes);
        for key in ["kind", "task_id", "m1", "input_sha256", "recorded_sha256"] {
            changed_spec_refused(&spec, key, None, &format!("spec is missing {key}"));
            changed_spec_refused(
                &spec,
                key,
                Some(json!(17)),
                &format!("spec {key} is not a string"),
            );
        }
        let uppercase = "A".repeat(64);
        let non_hex = "g".repeat(64);
        for key in ["input_sha256", "recorded_sha256"] {
            for bad in ["abc", uppercase.as_str(), non_hex.as_str()] {
                changed_spec_refused(
                    &spec,
                    key,
                    Some(json!(bad)),
                    &format!("spec {key} is not a sha256 hex"),
                );
            }
        }
        for key in [schema_key, "reasons", "fixed_strings"] {
            changed_spec_refused(&spec, key, None, &format!("spec is missing {key}"));
            changed_spec_refused(
                &spec,
                key,
                Some(json!("empty")),
                &format!("spec {key} is not an array"),
            );
            changed_spec_refused(
                &spec,
                key,
                Some(json!([17])),
                &format!("spec {key} holds a non-string"),
            );
        }
        changed_spec_refused(
            &spec,
            "kind",
            Some(json!("unknown")),
            "spec kind unknown is unknown",
        );
        changed_spec_refused(
            &spec,
            "extra",
            Some(json!(true)),
            "spec has unexpected key extra",
        );
        changed_spec_refused(
            &spec,
            schema_key,
            Some(json!([])),
            &format!("spec {schema_key} is empty"),
        );
        changed_spec_refused(
            &spec,
            schema_key,
            Some(json!(["duplicate", "duplicate"])),
            &format!("spec {schema_key} repeats duplicate"),
        );
        changed_spec_refused(
            &spec,
            "reasons",
            Some(json!(["unknown"])),
            "spec reason unknown is unknown",
        );
        let mut reordered = REASONS.to_vec();
        reordered.swap(0, 1);
        let mut duplicated = REASONS.to_vec();
        duplicated.push("mismatch");
        let mut invalid_orders = vec![Vec::new(), reordered, duplicated];
        for omitted in REASONS {
            invalid_orders.push(
                REASONS
                    .iter()
                    .copied()
                    .filter(|reason| *reason != omitted)
                    .collect(),
            );
        }
        for reasons in invalid_orders {
            changed_spec_refused(
                &spec,
                "reasons",
                Some(json!(reasons)),
                "spec reasons are not the canonical checks",
            );
        }
    }
    for spec in [&a_spec, &b_spec] {
        assert_eq!(spec.m1(), M1);
        let labels: Vec<&str> = spec.reasons().iter().map(|reason| reason.label()).collect();
        assert_eq!(labels, REASONS);
        assert_eq!(spec.fixed_strings(), FIXED_STRINGS);
    }
    assert_eq!(a_spec.input_sha256(), sha256_hex(&a_input));
    assert_eq!(b_spec.input_sha256(), sha256_hex(&b_input));
    assert_eq!(a_spec.recorded_sha256(), sha256_hex(&a_recorded));
    assert_eq!(b_spec.recorded_sha256(), sha256_hex(&b_recorded));
    assert_eq!(a_spec.task_id(), "agent-a");
    assert_eq!(b_spec.task_id(), "agent-b");
    assert_eq!(
        a_spec.schema(),
        &Schema::Fields(["place", "goods", "close"].map(str::to_owned).to_vec())
    );
    assert_eq!(
        b_spec.schema(),
        &Schema::Items(["date", "text"].map(str::to_owned).to_vec())
    );

    assert_eq!(
        judge(&a_spec, &a_input, &a_recorded, &a_recorded),
        accepted(&a_recorded)
    );
    assert_eq!(
        judge(&b_spec, &b_input, &b_recorded, &b_recorded),
        accepted(&b_recorded)
    );

    let mut other_m1 = parsed(&read("tasks/agent-a/accept.json"));
    other_m1
        .as_object_mut()
        .unwrap()
        .insert("m1".to_owned(), json!("other"));
    let other_m1 = load_spec(&other_m1.to_string()).expect("the other-m1 spec parses");
    assert_eq!(
        judge(&other_m1, &a_input, &a_recorded, &a_recorded),
        refused("task"),
        "a spec with another m1 is not a named task"
    );

    let a_substitute_input = "The stall on Pine Street opens at 10:00.";
    let a_substitute_recorded = r#"{"place":"Pine Street","goods":"pears","close":"14:00"}"#;
    let mut a_substitute = parsed(&read("tasks/agent-a/accept.json"));
    {
        let object = a_substitute.as_object_mut().unwrap();
        object.insert(
            "input_sha256".to_owned(),
            json!(sha256_hex(a_substitute_input)),
        );
        object.insert(
            "recorded_sha256".to_owned(),
            json!(sha256_hex(a_substitute_recorded)),
        );
    }
    let a_substitute =
        load_spec(&a_substitute.to_string()).expect("the agent-a substitute spec parses");
    assert_eq!(
        judge(
            &a_substitute,
            a_substitute_input,
            a_substitute_recorded,
            a_substitute_recorded
        ),
        refused("task"),
        "a self-consistent agent-a substitute is not a named task"
    );

    let b_substitute_input = "2026-04-01 other stall";
    let b_substitute_recorded = r#"{"items":[{"date":"2026-04-01","text":"other stall"}]}"#;
    let mut b_substitute = parsed(&read("tasks/agent-b/accept.json"));
    {
        let object = b_substitute.as_object_mut().unwrap();
        object.insert(
            "input_sha256".to_owned(),
            json!(sha256_hex(b_substitute_input)),
        );
        object.insert(
            "recorded_sha256".to_owned(),
            json!(sha256_hex(b_substitute_recorded)),
        );
    }
    let b_substitute =
        load_spec(&b_substitute.to_string()).expect("the agent-b substitute spec parses");
    assert_eq!(
        judge(
            &b_substitute,
            b_substitute_input,
            b_substitute_recorded,
            b_substitute_recorded
        ),
        refused("task"),
        "a self-consistent agent-b substitute is not a named task"
    );

    let a_changed = a_input.replacen("Oak", "Ook", 1);
    assert_ne!(sha256_hex(&a_changed), sha256_hex(&a_input));
    assert_eq!(
        judge(&a_spec, &a_changed, &a_recorded, &a_recorded),
        refused("input"),
        "changed input is input"
    );
    let b_changed = b_input.replacen("2026-03-14", "2026-03-13", 1);
    assert_ne!(sha256_hex(&b_changed), sha256_hex(&b_input));
    assert_eq!(
        judge(&b_spec, &b_changed, &b_recorded, &b_recorded),
        refused("input"),
        "changed input is input"
    );

    let a_substitute = r#"{"place":"Pine Street","goods":"apples","close":"13:00"}"#;
    assert_eq!(
        judge(&a_spec, &a_input, a_substitute, a_substitute),
        refused("recorded"),
        "agent-a substitute against its own hash is recorded"
    );
    let b_substitute = r#"{"items":[{"date":"2026-03-16","text":"stall opens"},{"date":"2026-03-15","text":"crate list due"}]}"#;
    assert_eq!(
        judge(&b_spec, &b_input, b_substitute, b_substitute),
        refused("recorded"),
        "agent-b substitute against its own hash is recorded"
    );

    for spec in [&a_spec, &b_spec] {
        let (input, expected) = if spec.task_id() == "agent-a" {
            (&a_input, &a_recorded)
        } else {
            (&b_input, &b_recorded)
        };
        for blank in ["", "   ", "\r\n \t"] {
            assert_eq!(
                judge(spec, input, expected, blank),
                refused("empty"),
                "blank answer is empty"
            );
        }
        for wrapped in [format!("\t{expected}"), format!("{expected}\r")] {
            assert_eq!(
                judge(spec, input, expected, &wrapped),
                accepted(&wrapped),
                "JSON whitespace around an answer is accepted"
            );
        }
        for wrapped in [
            format!("\u{00a0}{expected}"),
            format!("\u{000b}{expected}"),
            format!("{expected}\u{000c}"),
            format!("\u{feff}{expected}"),
        ] {
            assert_eq!(
                judge(spec, input, expected, &wrapped),
                refused("shape"),
                "non-JSON whitespace around an answer is shape"
            );
        }
        assert_eq!(
            judge(spec, input, expected, "\u{00a0}ok"),
            refused("shape"),
            "a fixed string behind U+00A0 is shape"
        );
        assert_eq!(
            judge(spec, input, expected, input),
            refused("echo"),
            "raw input is an echo"
        );
        for fixed in FIXED_STRINGS {
            assert_eq!(
                judge(spec, input, expected, fixed),
                refused("fixed-string"),
                "fixed string {fixed}"
            );
        }
        assert_eq!(
            judge(spec, input, expected, &format!("  {}  ", input.trim())),
            refused("echo"),
            "padded echo trims to the input"
        );
    }

    let a_answers = [
        (
            r#"{"place":"Oak Street","goods":"apples"}"#,
            refused("shape"),
        ),
        (
            r#"{"place":"Pine Street","goods":"apples","close":"13:00"}"#,
            refused("mismatch"),
        ),
        (r#"{"place":}"#, refused("shape")),
        (
            r#"{"place":"Oak Street","goods":"apples","close":"13:00","owner":"stall"}"#,
            refused("shape"),
        ),
        (
            r#"{"place":"Oak Street","goods":"apples","close":13}"#,
            refused("shape"),
        ),
        (r#"["Oak Street","apples","13:00"]"#, refused("shape")),
        (
            r#"{"place":"Pine Street","goods":"apples","close":"13:00","place":"Oak Street"}"#,
            refused("duplicate"),
        ),
        (
            r#"{"place":"Pine Street","goods":"apples","close":"13:00","\u0070lace":"Oak Street"}"#,
            refused("duplicate"),
        ),
        (
            r#"{"place":"Oak Street","goods":"apples","close":"13:00","place":"Pine Street"}"#,
            refused("duplicate"),
        ),
        (
            r#"{"place":"Oak Street","goods":"apples","close":"13:00","owner":"stall","owner":"stall"}"#,
            refused("duplicate"),
        ),
        (
            r#"{"place":"Oak Street","goods":"apples \"place\"","close":"13:00"}"#,
            refused("mismatch"),
        ),
        (
            r#"{"place":"Oak Street","goods":"apples","close":"13:00"} x"#,
            refused("shape"),
        ),
    ];
    for (answer, verdict) in a_answers {
        assert_eq!(
            judge(&a_spec, &a_input, &a_recorded, answer),
            verdict,
            "agent-a answer {answer}"
        );
    }

    let b_answers = [
        (
            r#"{"items":[{"date":"2026-03-14","text":"stall opens"},{"date":"2026-03-15"}]}"#,
            refused("shape"),
        ),
        (
            r#"{"items":[{"date":"2026-03-16","text":"stall opens"},{"date":"2026-03-15","text":"crate list due"}]}"#,
            refused("mismatch"),
        ),
        (r#"{"items":[}"#, refused("shape")),
        (
            r#"{"items":[{"date":"2026-03-14","text":"stall opens"},{"date":"2026-03-15","text":"crate list due"}],"count":2}"#,
            refused("shape"),
        ),
        (
            r#"{"items":[{"date":"2026-03-14","text":"stall opens"},{"date":"2026-03-15","text":7}]}"#,
            refused("shape"),
        ),
        (r#"{"items":"stall opens"}"#, refused("shape")),
        (r#"{}"#, refused("shape")),
        (r#"[]"#, refused("shape")),
        (r#"{"items":[17]}"#, refused("shape")),
        (
            r#"{"items":[{"date":"2026-03-14","text":"stall opens","extra":"value"}]}"#,
            refused("shape"),
        ),
        (
            r#"{"items":[{"date":"2026-03-16","text":"stall opens","date":"2026-03-14"},{"date":"2026-03-15","text":"crate list due"}]}"#,
            refused("duplicate"),
        ),
    ];
    for (answer, verdict) in b_answers {
        assert_eq!(
            judge(&b_spec, &b_input, &b_recorded, answer),
            verdict,
            "agent-b answer {answer}"
        );
    }

    let a_equivalent =
        " { \"goods\" : \"apples\",\n  \"close\": \"13:00\", \"place\": \"Oak Street\" } ";
    assert_eq!(
        judge(&a_spec, &a_input, &a_recorded, a_equivalent),
        accepted(a_equivalent),
        "equivalent JSON with other formatting and key order is accepted"
    );
    let b_equivalent = "{\n \"items\": [ {\"text\": \"stall opens\", \"date\": \"2026-03-14\"}, {\"date\": \"2026-03-15\", \"text\": \"crate list due\"} ]\n}";
    assert_eq!(
        judge(&b_spec, &b_input, &b_recorded, b_equivalent),
        accepted(b_equivalent),
        "equivalent items JSON with other formatting and key order is accepted"
    );

    assert_eq!(
        judge(&b_spec, &b_input, &b_recorded, &a_recorded),
        refused("shape"),
        "agent-a answer against agent-b spec"
    );
    assert_eq!(
        judge(&a_spec, &a_input, &a_recorded, &b_recorded),
        refused("shape"),
        "agent-b answer against agent-a spec"
    );

    let source = include_str!("../src/lib.rs");
    assert!(!source.contains("std::fs"));
    assert!(!source.contains("std::net"));
}
