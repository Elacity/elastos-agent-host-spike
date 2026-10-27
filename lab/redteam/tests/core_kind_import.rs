use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};

use wasm_capsule_audit::{audit, DeclaredImport, Refusal};

#[path = "support.rs"]
mod support;

use support::*;

const GLOBAL_IMPORT: &str = r#"(module (import "env" "g" (global i32)))"#;
const TABLE_IMPORT: &str = r#"(module (import "env" "t" (table 1 funcref)))"#;

#[test]
fn global_import_is_refused() {
    assert_global_fixture();
    let wasm = wat::parse_str(GLOBAL_IMPORT).expect("fixture parses");
    let attribution = read_live_attribution(GLOBAL_FINDING_ID);
    let detail = accept_detail("global", GLOBAL_IMPORT);
    let finding = finding_path(GLOBAL_FINDING_FILE);
    match audit(&wasm, &[]) {
        Err(
            ref refusal @ Refusal::Undeclared {
                module: ref import_module,
                name: ref import_name,
            },
        ) => {
            assert_eq!(import_module, "env");
            assert_eq!(import_name, "g");
            assert_eq!(refusal.to_string(), "undeclared import env.g");
            record_outcome(false, &finding, &attribution, &detail).expect("record refusal");
            assert_no_finding(&finding);
        }
        Ok(listed) => {
            record_outcome(true, &finding, &attribution, &detail).expect("record accept");
            panic!("accepted undeclared global import: {listed:?}");
        }
        Err(refusal) => panic!("failure, not a skip: {refusal}"),
    }
}

#[test]
fn declared_global_import_is_listed() {
    assert_global_fixture();
    let wasm = wat::parse_str(GLOBAL_IMPORT).expect("fixture parses");
    let declared = DeclaredImport {
        module: "env".to_string(),
        name: "g".to_string(),
    };
    let listed =
        audit(&wasm, std::slice::from_ref(&declared)).expect("declared global import is listed");
    assert_eq!(listed, vec![declared.clone()]);
    // The cargo plant runs only global_import_is_refused. Dropping g from a
    // declared result stays green there.
    let dropped = falsifier_drops_name(&listed, "g");
    let caught = catch_unwind(AssertUnwindSafe(|| assert_eq!(dropped, vec![declared])));
    assert!(
        caught.is_err(),
        "a falsifier that drops g from the declared list was not caught"
    );
}

#[test]
fn global_anchor_guard_is_enforced() {
    // plant_at does not run cargo. Zero and two anchors are skips.
    assert_anchor_counts_skip("Global");
}

#[test]
fn global_plant_changes_only_global_imports() {
    assert_one_kind_plant(
        "Global",
        &["TypeRef::Global", "TypeRef::Memory"],
        &["TypeRef::Table"],
    );
}

#[test]
fn skipped_global_import_is_caught() {
    run_skipped_plant(&global_probe());
}

#[test]
fn table_import_is_refused() {
    assert_table_fixture();
    let wasm = wat::parse_str(TABLE_IMPORT).expect("fixture parses");
    let attribution = read_live_attribution(TABLE_FINDING_ID);
    let detail = accept_detail("table", TABLE_IMPORT);
    let finding = finding_path(TABLE_FINDING_FILE);
    match audit(&wasm, &[]) {
        Err(
            ref refusal @ Refusal::Undeclared {
                module: ref import_module,
                name: ref import_name,
            },
        ) => {
            assert_eq!(import_module, "env");
            assert_eq!(import_name, "t");
            assert_eq!(refusal.to_string(), "undeclared import env.t");
            record_outcome(false, &finding, &attribution, &detail).expect("record refusal");
            assert_no_finding(&finding);
        }
        Ok(listed) => {
            record_outcome(true, &finding, &attribution, &detail).expect("record accept");
            panic!("accepted undeclared table import: {listed:?}");
        }
        Err(refusal) => panic!("failure, not a skip: {refusal}"),
    }
}

#[test]
fn declared_table_import_is_listed() {
    assert_table_fixture();
    let wasm = wat::parse_str(TABLE_IMPORT).expect("fixture parses");
    let declared = DeclaredImport {
        module: "env".to_string(),
        name: "t".to_string(),
    };
    let listed =
        audit(&wasm, std::slice::from_ref(&declared)).expect("declared table import is listed");
    assert_eq!(listed, vec![declared.clone()]);
    // The cargo plant runs only table_import_is_refused. Dropping t from a
    // declared result stays green there.
    let dropped = falsifier_drops_name(&listed, "t");
    let caught = catch_unwind(AssertUnwindSafe(|| assert_eq!(dropped, vec![declared])));
    assert!(
        caught.is_err(),
        "a falsifier that drops t from the declared list was not caught"
    );
}

#[test]
fn table_anchor_guard_is_enforced() {
    // plant_at does not run cargo. Zero and two anchors are skips.
    assert_anchor_counts_skip("Table");
}

#[test]
fn table_plant_changes_only_table_imports() {
    assert_one_kind_plant(
        "Table",
        &["TypeRef::Table", "TypeRef::Memory"],
        &["TypeRef::Global"],
    );
}

#[test]
fn skipped_table_import_is_caught() {
    run_skipped_plant(&table_probe());
}

#[test]
fn core_finding_details_name_core_imports() {
    for (kind, fixture) in [("global", GLOBAL_IMPORT), ("table", TABLE_IMPORT)] {
        let detail = accept_detail(kind, fixture);
        let expected = format!(
            "accepted an undeclared core {kind} import\nfixture: {fixture}\ndeclarations: empty"
        );
        assert_eq!(detail, expected);
        let restored = falsifier_labels_core_import_as_component(kind, fixture);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_eq!(restored, expected)));
        assert!(
            caught.is_err(),
            "a falsifier that labels a core {kind} import as a component was not caught"
        );
    }
    assert_eq!(
        accept_detail("function", "env"),
        "accepted an undeclared component function import\nfixture: env\ndeclarations: empty"
    );
}

fn assert_anchor_counts_skip(type_name: &str) {
    let replacement = core_skip_replacement(type_name);
    for count in [0, 2] {
        let source = CORE_ANCHOR.repeat(count);
        let plant = plant_at(&source, CORE_ANCHOR, &replacement);
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

fn assert_one_kind_plant(type_name: &str, present: &[&str], absent: &[&str]) {
    let source = fs::read_to_string(audit_lib()).expect("read live audit");
    let planted = match plant_at(&source, CORE_ANCHOR, &core_skip_replacement(type_name)) {
        Plant::Source(text) => text,
        Plant::Skip(reason) => panic!("one anchor skipped: {reason}"),
    };
    assert_core_skip_shape(&source, &planted, type_name);
    for needle in present {
        assert!(
            planted.contains(needle),
            "{needle} missing from the {type_name} plant"
        );
    }
    for needle in absent {
        assert!(
            !planted.contains(needle),
            "{needle} present in the {type_name} plant"
        );
    }
    // Replacing the push with continue drops every import. The planted cargo
    // test only runs the empty-list refusal, so that broader edit fails the
    // same expect_err. The shape check is what rejects it.
    let removed = falsifier_replaces_push_with_continue(&source);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert_core_skip_shape(&source, &removed, type_name)
    }));
    assert!(
        caught.is_err(),
        "a falsifier that replaces the push with continue; was not caught"
    );
    // The component anchor occurs once in the live library. Planting it leaves
    // the core push in place, so the empty-list refusal still passes. The
    // shape check is what rejects that plant.
    let wrong_anchor = match plant_at(&source, ANCHOR, &core_skip_replacement(type_name)) {
        Plant::Source(text) => text,
        Plant::Skip(reason) => panic!("component anchor skipped: {reason}"),
    };
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert_core_skip_shape(&source, &wrong_anchor, type_name)
    }));
    assert!(
        caught.is_err(),
        "a falsifier that plants ANCHOR instead of CORE_ANCHOR was not caught"
    );
}

fn global_probe() -> PlantedProbe {
    let test_source = core_refusal_test_source("global_import_is_refused", GLOBAL_IMPORT);
    assert_core_refusal_source(&test_source);
    PlantedProbe {
        anchor: CORE_ANCHOR,
        replacement: core_skip_replacement("Global"),
        assert_shape: assert_global_skip_shape,
        test_file: "redteam_global_import.rs",
        test_source,
        test_binary: "redteam_global_import",
        exact_test: "global_import_is_refused",
    }
}

fn table_probe() -> PlantedProbe {
    let test_source = core_refusal_test_source("table_import_is_refused", TABLE_IMPORT);
    assert_core_refusal_source(&test_source);
    PlantedProbe {
        anchor: CORE_ANCHOR,
        replacement: core_skip_replacement("Table"),
        assert_shape: assert_table_skip_shape,
        test_file: "redteam_table_import.rs",
        test_source,
        test_binary: "redteam_table_import",
        exact_test: "table_import_is_refused",
    }
}

fn assert_global_skip_shape(original: &str, planted: &str) {
    assert_core_skip_shape(original, planted, "Global");
}

fn assert_table_skip_shape(original: &str, planted: &str) {
    assert_core_skip_shape(original, planted, "Table");
}

fn assert_core_refusal_source(source: &str) {
    assert!(source.contains("wasm_capsule_audit::audit(&wasm, &[])"));
    assert!(source.contains("expect_err(\"must refuse\")"));
    assert!(!source.contains("audit_component"), "{source}");
    assert!(!source.contains("UndeclaredInterface"), "{source}");
}

fn assert_global_fixture() {
    assert!(
        GLOBAL_IMPORT.contains("(global i32)"),
        "fixture is a global import"
    );
    assert!(
        !GLOBAL_IMPORT.contains("(func)"),
        "fixture is not a function import"
    );
    assert!(
        !GLOBAL_IMPORT.contains("(memory"),
        "fixture is not a memory import"
    );
    assert!(
        !GLOBAL_IMPORT.contains("(table"),
        "fixture is not a table import"
    );
}

fn assert_table_fixture() {
    assert!(
        TABLE_IMPORT.contains("(table 1 funcref)"),
        "fixture is a table import"
    );
    assert!(
        !TABLE_IMPORT.contains("(func)"),
        "fixture is not a function import"
    );
    assert!(
        !TABLE_IMPORT.contains("(memory"),
        "fixture is not a memory import"
    );
    assert!(
        !TABLE_IMPORT.contains("(global"),
        "fixture is not a global import"
    );
}

fn falsifier_drops_name(listed: &[DeclaredImport], name: &str) -> Vec<DeclaredImport> {
    listed
        .iter()
        .filter(|import| import.name != name)
        .cloned()
        .collect()
}

fn falsifier_bypasses_count_guard(source: &str, replacement: &str) -> Plant {
    Plant::Source(source.replacen(CORE_ANCHOR, replacement, 1))
}

fn falsifier_replaces_push_with_continue(source: &str) -> String {
    source.replacen(CORE_ANCHOR, "continue;", 1)
}

fn falsifier_labels_core_import_as_component(kind: &str, fixture: &str) -> String {
    format!(
        "accepted an undeclared component {kind} import\nfixture: {fixture}\ndeclarations: empty"
    )
}
