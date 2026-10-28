use std::path::PathBuf;

use serde_json::{json, Value};
use useful_task::{judge, load_spec, sha256_hex, Schema, Verdict};

const M1: &str = "A4: Each agent completes one useful task through real Runtime resources (model via a Runtime grant, DeepSeek on the Sparks); the permitted effect succeeds (granted_effect_succeeds).";
const REASONS: [&str; 5] = ["empty", "echo", "fixed-string", "shape", "mismatch"];
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

    let a_spec = load_spec(&read("tasks/agent-a/accept.json")).expect("agent-a spec parses");
    let b_spec = load_spec(&read("tasks/agent-b/accept.json")).expect("agent-b spec parses");
    refused_spec(
        "[",
        "spec is not JSON: EOF while parsing a list at line 1 column 1",
    );
    refused_spec("null", "spec is not an object");
    for (bytes, schema_key) in [
        (read("tasks/agent-a/accept.json"), "fields"),
        (read("tasks/agent-b/accept.json"), "item_fields"),
    ] {
        let spec = parsed(&bytes);
        for key in ["kind", "task_id", "m1", "input_sha256"] {
            changed_spec_refused(&spec, key, None, &format!("spec is missing {key}"));
            changed_spec_refused(
                &spec,
                key,
                Some(json!(17)),
                &format!("spec {key} is not a string"),
            );
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

    let a_expected = parsed(&a_recorded);
    let b_expected = parsed(&b_recorded);
    assert_eq!(
        judge(&a_spec, &a_input, &a_expected, &a_recorded),
        accepted(&a_recorded)
    );
    assert_eq!(
        judge(&b_spec, &b_input, &b_expected, &b_recorded),
        accepted(&b_recorded)
    );

    for spec in [&a_spec, &b_spec] {
        let (input, expected) = if spec.task_id() == "agent-a" {
            (&a_input, &a_expected)
        } else {
            (&b_input, &b_expected)
        };
        for blank in ["", "   "] {
            assert_eq!(
                judge(spec, input, expected, blank),
                refused("empty"),
                "blank answer is empty"
            );
        }
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
    ];
    for (answer, verdict) in a_answers {
        assert_eq!(
            judge(&a_spec, &a_input, &a_expected, answer),
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
    ];
    for (answer, verdict) in b_answers {
        assert_eq!(
            judge(&b_spec, &b_input, &b_expected, answer),
            verdict,
            "agent-b answer {answer}"
        );
    }

    let a_equivalent =
        " { \"goods\" : \"apples\",\n  \"close\": \"13:00\", \"place\": \"Oak Street\" } ";
    assert_eq!(
        judge(&a_spec, &a_input, &a_expected, a_equivalent),
        accepted(a_equivalent),
        "equivalent JSON with other formatting and key order is accepted"
    );
    let b_equivalent = "{\n \"items\": [ {\"text\": \"stall opens\", \"date\": \"2026-03-14\"}, {\"date\": \"2026-03-15\", \"text\": \"crate list due\"} ]\n}";
    assert_eq!(
        judge(&b_spec, &b_input, &b_expected, b_equivalent),
        accepted(b_equivalent),
        "equivalent items JSON with other formatting and key order is accepted"
    );

    assert_eq!(
        judge(&b_spec, &b_input, &b_expected, &a_recorded),
        refused("shape"),
        "agent-a answer against agent-b spec"
    );
    assert_eq!(
        judge(&a_spec, &a_input, &a_expected, &b_recorded),
        refused("shape"),
        "agent-b answer against agent-a spec"
    );

    let source = include_str!("../src/lib.rs");
    assert!(!source.contains("std::fs"));
    assert!(!source.contains("std::net"));
}
