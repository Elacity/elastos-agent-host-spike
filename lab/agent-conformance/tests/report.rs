use agent_conformance::report::table;

#[test]
fn run_table_requires_cargo_results() {
    let listed = "works: test\nblocked: test\n";
    let output = "test works ... ok\ntest blocked ... ignored, blocked: RT3 model grant\n";
    assert_eq!(
        table(listed, output, true),
        (
            "test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\nblocked | BLOCKED (RT3)\nworks | PASS\n".into(),
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
            (
                "test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncase | FAIL\n".into(),
                false
            )
        );
    }
    assert!(!table(listed, output, false).1);
    assert!(!table("", "test unlisted ... ok\n", true).1);
    assert!(!table("", "", true).1);
    assert!(!table("case: test\ncase: test\n", "test case ... ok\n", true).1);
    let name = "process_isolation::parallel_instances_complete_independently";
    assert_eq!(
        table(
            &format!("{name}: test\n"),
            &format!("test {name} ... ok\n"),
            true
        )
        .0,
        format!("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\n{name} | PASS\n")
    );
}

#[test]
fn run_table_grades_skipped_only_with_failed_test() {
    let marker = "SKIPPED case: loopback bind refused\n";
    for cargo_ok in [false, true] {
        let (text, passed) = table(
            "case: test\n",
            &format!("{marker}test case ... FAILED\n"),
            cargo_ok,
        );
        assert!(!passed);
        assert!(text.contains("case | SKIPPED (loopback bind refused)\n"));
    }
    for result in ["ok", "ignored, blocked: RT3", "unknown", ""] {
        let (text, passed) = table(
            "case: test\n",
            &format!("{marker}test case ... {result}\n"),
            true,
        );
        assert!(!passed);
        assert!(text.contains("case | FAIL\n"));
    }
    for output in [
        marker.to_owned(),
        format!("{marker}{marker}test case ... FAILED\n"),
        "SKIPPED case: \ntest case ... FAILED\n".into(),
        "test case ... FAILED\nRuntime refusal\n".into(),
    ] {
        let (text, passed) = table("case: test\n", &output, false);
        assert!(!passed);
        assert!(text.contains("case | FAIL\n"));
    }
    assert!(table("", &format!("{marker}test case ... FAILED\n"), false)
        .0
        .contains("case | FAIL\n"));
}
