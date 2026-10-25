use agent_conformance::report::table;

#[test]
fn run_table_requires_cargo_results() {
    let listed = "works: test\nblocked: test\n";
    let output = "test works ... ok\ntest blocked ... ignored, blocked: RT3 model grant\n";
    assert_eq!(
        table(listed, output, true),
        (
            "test | PASS/FAIL/BLOCKED (id)\nblocked | BLOCKED (RT3)\nworks | PASS\n".into(),
            true
        )
    );
    for result in ["FAILED", "ignored", "ignored, blocked: ", "", "unknown"] {
        let (text, passed) = table("case: test\n", &format!("test case ... {result}\n"), true);
        assert!(!passed, "result must fail: {result}");
        assert!(text.contains("case | FAIL\n"));
    }
    for output in ["", "test case ... ok\ntest case ... ok\n"] {
        assert_eq!(
            table("case: test\n", output, true),
            ("test | PASS/FAIL/BLOCKED (id)\ncase | FAIL\n".into(), false)
        );
    }
    assert!(!table(listed, output, false).1);
    assert!(!table("", "test unlisted ... ok\n", true).1);
    assert!(!table("", "", true).1);
    assert!(!table("case: test\ncase: test\n", "test case ... ok\n", true).1);
}
