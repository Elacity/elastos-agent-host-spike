use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};

use wasm_capsule_audit::{audit_component, Refusal};

#[path = "support.rs"]
mod support;

use support::*;

const COMPONENT_KIND_IMPORT: &str = r#"(component (import "env" (component)))"#;

#[test]
fn component_kind_import_is_refused() {
    assert_component_kind_fixture();
    let wasm = wat::parse_str(COMPONENT_KIND_IMPORT).expect("fixture parses");
    let attribution = read_live_attribution(COMPONENT_FINDING_ID);
    let detail = accept_detail("component-kind", COMPONENT_KIND_IMPORT);
    let finding = finding_path(COMPONENT_FINDING_FILE);
    match audit_component(&wasm, &[]) {
        Err(ref refusal @ Refusal::UndeclaredInterface { ref name }) => {
            assert_eq!(name, "env");
            assert_eq!(refusal.to_string(), "undeclared interface env");
            record_outcome(false, &finding, &attribution, &detail).expect("record refusal");
            assert_no_finding(&finding);
        }
        Ok(listed) => {
            record_outcome(true, &finding, &attribution, &detail).expect("record accept");
            panic!("accepted undeclared component-kind import: {listed:?}");
        }
        Err(refusal) => panic!("failure, not a skip: {refusal}"),
    }
}

#[test]
fn declared_component_kind_import_is_listed() {
    assert_component_kind_fixture();
    let wasm = wat::parse_str(COMPONENT_KIND_IMPORT).expect("fixture parses");
    let listed =
        audit_component(&wasm, &["env"]).expect("declared component-kind import is listed");
    assert_eq!(listed, vec!["env".to_string()]);
    // The cargo plant runs only component_kind_import_is_refused. Dropping env
    // from a declared result stays green there.
    let dropped = falsifier_drops_env(&listed);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert_eq!(dropped, vec!["env".to_string()]);
    }));
    assert!(
        caught.is_err(),
        "a falsifier that drops env from the declared list was not caught"
    );
}

#[test]
fn component_kind_anchor_guard_is_enforced() {
    // plant_edit does not run cargo. Zero and two anchors are skips.
    let replacement = type_skip_replacement("Component");
    for count in [0, 2] {
        let source = ANCHOR.repeat(count);
        let plant = plant_edit(&source, &replacement);
        match &plant {
            Plant::Skip(reason) => assert!(reason.contains(SKIP_MARK), "{reason}"),
            Plant::Source(text) => panic!("count {count} planted: {text}"),
        }
        let bypass = falsifier_bypasses_count_guard(&source, &replacement);
        let caught = catch_unwind(AssertUnwindSafe(|| match &bypass {
            Plant::Skip(reason) => assert!(reason.contains(SKIP_MARK), "{reason}"),
            Plant::Source(text) => panic!("count guard bypassed: {text}"),
        }));
        assert!(
            caught.is_err(),
            "a falsifier that bypasses the count guard was not caught"
        );
        let report = report_plant(&plant);
        assert_skip_report(&report);
        let passed = falsifier_reports_skip_as_pass(&plant);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_skip_report(&passed)));
        assert!(
            caught.is_err(),
            "a falsifier that reports the skipped plant as passed was not caught"
        );
    }
}

#[test]
fn component_kind_plant_changes_only_component_imports() {
    let source = fs::read_to_string(audit_lib()).expect("read live audit");
    let planted = match plant_edit(&source, &type_skip_replacement("Component")) {
        Plant::Source(text) => text,
        Plant::Skip(reason) => panic!("one anchor skipped: {reason}"),
    };
    assert_component_kind_skip_shape(&source, &planted);
    // Replacing the push with continue drops every import. The planted cargo
    // test only runs component_kind_import_is_refused, so that broader edit
    // fails the same expect_err. The shape check is what rejects it.
    let removed = falsifier_removes_every_import(&source);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert_component_kind_skip_shape(&source, &removed)
    }));
    assert!(
        caught.is_err(),
        "a falsifier that removes every import was not caught"
    );
}

#[test]
fn skipped_component_kind_import_is_caught() {
    run_skipped_plant(&component_kind_probe());
}

fn assert_component_kind_fixture() {
    assert!(
        COMPONENT_KIND_IMPORT.contains("(import \"env\" (component))"),
        "fixture is a component-kind import"
    );
    assert!(
        !COMPONENT_KIND_IMPORT.contains("(func)"),
        "fixture is not a function import"
    );
    assert!(
        !COMPONENT_KIND_IMPORT.contains("(instance)"),
        "fixture is not an instance import"
    );
    assert!(
        !COMPONENT_KIND_IMPORT.contains("(core module)"),
        "fixture is not a core-module import"
    );
    assert!(
        !COMPONENT_KIND_IMPORT.contains("(type "),
        "fixture is not a type import"
    );
    assert!(
        !COMPONENT_KIND_IMPORT.contains("(value "),
        "fixture is not a value import"
    );
    assert!(
        COMPONENT_KIND_IMPORT.contains("\"env\""),
        "import name is env"
    );
}

fn assert_component_kind_skip_shape(original: &str, planted: &str) {
    assert_type_skip_shape(original, planted, "Component");
}

fn component_kind_probe() -> PlantedProbe {
    PlantedProbe {
        anchor: ANCHOR,
        replacement: type_skip_replacement("Component"),
        assert_shape: assert_component_kind_skip_shape,
        test_file: "redteam_component_kind_import.rs",
        test_source: refusal_test_source("component_kind_import_is_refused", COMPONENT_KIND_IMPORT),
        test_binary: "redteam_component_kind_import",
        exact_test: "component_kind_import_is_refused",
    }
}

fn falsifier_drops_env(listed: &[String]) -> Vec<String> {
    listed
        .iter()
        .filter(|name| name.as_str() != "env")
        .cloned()
        .collect()
}

fn falsifier_bypasses_count_guard(source: &str, replacement: &str) -> Plant {
    Plant::Source(source.replacen(ANCHOR, replacement, 1))
}

fn falsifier_removes_every_import(source: &str) -> String {
    source.replacen(ANCHOR, "continue;", 1)
}
