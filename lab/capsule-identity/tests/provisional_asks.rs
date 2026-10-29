//! The one provisional `asks.json` parse, `provisional_asks` in `common`: the
//! lab stand-in schema, a closed declaration and ask shape, a non-empty `kind`
//! and `resource`, and file order. The stand-in's launch that reads this parse
//! is checked in `tests/stand_in.rs`.
mod common;

use common::*;

#[test]
fn provisional_asks_reads_the_committed_declaration_in_file_order() {
    let signed = read_fixture(&AGENT_HOST, "asks.json");
    let parsed = provisional_asks(&signed).expect("the committed declaration parses");
    assert_eq!(parsed, value_asks(&signed));
    assert_eq!(
        parsed
            .first()
            .map(|(kind, resource)| (kind.as_str(), resource.as_str())),
        Some(("read", "<principal>/"))
    );
    assert_eq!(parsed.len(), 9, "every committed ask is read");
}

#[test]
fn provisional_asks_refuses_a_wrong_schema() {
    let wrong = fixture_asks_text(&AGENT_HOST).replacen(
        r#""schema": "elastos.agent-host.asks/v1""#,
        r#""schema": "not-the-provisional-schema""#,
        1,
    );
    assert_eq!(
        provisional_asks(wrong.as_bytes()),
        Err(
            "asks declaration: schema is not-the-provisional-schema, not elastos.agent-host.asks/v1"
                .to_owned()
        )
    );
}

#[test]
fn provisional_asks_refuses_a_closed_shape() {
    for (body, case, expected) in [
        (
            r#"{"schema": "elastos.agent-host.asks/v1", "asks": [], "extra": 1}"#,
            "declaration field",
            "asks declaration: unknown field `extra`, expected `schema` or `asks` at line 1 column 60",
        ),
        (
            r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"kind": "read", "resource": "r", "extra": "x"}]}"#,
            "ask field",
            "asks declaration: unknown field `extra`, expected `kind` or `resource` at line 1 column 91",
        ),
        (
            r#"{"schema": "elastos.agent-host.asks/v1"}"#,
            "no asks",
            "asks declaration: missing field `asks` at line 1 column 40",
        ),
        (
            r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"resource": "r"}]}"#,
            "no kind",
            "asks declaration: missing field `kind` at line 1 column 67",
        ),
        (
            r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"kind": 5, "resource": "r"}]}"#,
            "kind not a string",
            "asks declaration: invalid type: integer `5`, expected a string at line 1 column 60",
        ),
        (
            r#"[]"#,
            "not an object",
            "asks declaration: invalid type: sequence, expected an asks declaration object at line 1 column 0",
        ),
        (
            r#"{"schema": "elastos.agent-host.asks/v1", "asks": {}}"#,
            "asks not an array",
            "asks declaration: invalid type: map, expected a sequence at line 1 column 49",
        ),
        (
            r#"not json"#,
            "not JSON",
            "asks declaration: expected ident at line 1 column 2",
        ),
        (
            r#"{"asks":[]}"#,
            "no schema",
            "asks declaration: missing field `schema` at line 1 column 11",
        ),
        (
            r#"{"schema":7,"asks":[]}"#,
            "schema not a string",
            "asks declaration: invalid type: integer `7`, expected a string at line 1 column 11",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[{"kind":"read"}]}"#,
            "no resource",
            "asks declaration: missing field `resource` at line 1 column 62",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[{"kind":"read","resource":7}]}"#,
            "resource not a string",
            "asks declaration: invalid type: integer `7`, expected a string at line 1 column 74",
        ),
        (
            r#"null"#,
            "null declaration",
            "asks declaration: invalid type: null, expected an asks declaration object at line 1 column 4",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[null]}"#,
            "null ask",
            "asks declaration: invalid type: null, expected an ask object at line 1 column 51",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":null}"#,
            "null asks",
            "asks declaration: invalid type: null, expected a sequence at line 1 column 50",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","schema":"elastos.agent-host.asks/v1","asks":[]}"#,
            "duplicate schema",
            "asks declaration: duplicate field `schema` at line 1 column 47",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[],"asks":[]}"#,
            "duplicate asks",
            "asks declaration: duplicate field `asks` at line 1 column 55",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[{"kind":"read","kind":"read","resource":"r"}]}"#,
            "duplicate kind",
            "asks declaration: duplicate field `kind` at line 1 column 68",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[{"kind":"read","resource":"r","resource":"r"}]}"#,
            "duplicate resource",
            "asks declaration: duplicate field `resource` at line 1 column 87",
        ),
        (
            r#"{"schema":"elastos.agent-host.asks/v1","asks":[]} {}"#,
            "trailing JSON",
            "asks declaration: trailing characters at line 1 column 51",
        ),
    ] {
        assert_eq!(provisional_asks(body.as_bytes()), Err(expected.to_owned()), "{case}");
        let reason = provisional_asks(body.as_bytes()).expect_err(case);
        assert!(
            reason.starts_with("asks declaration: "),
            "{case}: the shape refusal is its own text: {reason}"
        );
    }
}

#[test]
fn provisional_asks_refuses_an_array_declaration() {
    for body in [
        r#"["elastos.agent-host.asks/v1",[]]"#,
        r#"["elastos.agent-host.asks/v1",[{"kind":"read","resource":"<principal>/"}]]"#,
    ] {
        assert_eq!(
            provisional_asks(body.as_bytes()),
            Err("asks declaration: invalid type: sequence, expected an asks declaration object at line 1 column 0".to_owned()),
            "a declaration uses named fields: {body}"
        );
    }
}

#[test]
fn provisional_asks_refuses_an_array_ask() {
    for body in [
        r#"{"schema":"elastos.agent-host.asks/v1","asks":[["read","<principal>/"]]}"#,
        r#"{"schema":"elastos.agent-host.asks/v1","asks":[[]]}"#,
    ] {
        assert_eq!(
            provisional_asks(body.as_bytes()),
            Err("asks declaration: invalid type: sequence, expected an ask object at line 1 column 47".to_owned()),
            "each ask uses named fields: {body}"
        );
    }
}

#[test]
fn provisional_asks_refuses_an_empty_kind() {
    let body =
        r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"kind": "", "resource": "r"}]}"#;
    assert_eq!(
        provisional_asks(body.as_bytes()),
        Err("asks declaration: an ask has an empty kind".to_owned())
    );
}

#[test]
fn provisional_asks_refuses_an_empty_resource() {
    let body =
        r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"kind": "read", "resource": ""}]}"#;
    assert_eq!(
        provisional_asks(body.as_bytes()),
        Err("asks declaration: an ask has an empty resource".to_owned())
    );
}

#[test]
fn provisional_asks_keeps_the_declared_file_order() {
    let body = r#"{"schema": "elastos.agent-host.asks/v1", "asks": [{"kind": "b", "resource": "2"}, {"kind": "a", "resource": "1"}]}"#;
    assert_eq!(
        provisional_asks(body.as_bytes()),
        Ok(vec![
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
        ])
    );
}
