use wasm_capsule_audit::{audit_component, Refusal};

fn assert_undeclared(wasm: &[u8], declared: &[&str], name: &str) {
    let refusal =
        audit_component(wasm, declared).expect_err("undeclared interface must be refused");
    assert_eq!(refusal, Refusal::UndeclaredInterface { name: name.into() });
    assert_eq!(refusal.to_string(), format!("undeclared interface {name}"));
}

#[test]
fn component_importing_only_a_declared_interface_passes() {
    let declared = ["elastos:bus/log@1.0.0", "elastos:bus/runtime@1.0.0"];
    let one =
        wat::parse_str(r#"(component (import "elastos:bus/runtime@1.0.0" (instance)))"#).unwrap();
    assert_eq!(
        audit_component(&one, &declared),
        Ok(vec![declared[1].into()])
    );

    let two = wat::parse_str(
        r#"(component
            (import "elastos:bus/runtime@1.0.0" (instance))
            (import "elastos:bus/log@1.0.0" (instance)))"#,
    )
    .unwrap();
    assert_eq!(
        audit_component(&two, &declared),
        Ok(vec![declared[1].into(), declared[0].into()])
    );
}

#[test]
fn component_importing_wasi_filesystem_is_refused_by_name() {
    let wasm = wat::parse_str(
        r#"(component
            (import "wasi:filesystem/types@0.2.0" (instance))
            (core module))"#,
    )
    .unwrap();
    assert_undeclared(&wasm, &[], "wasi:filesystem/types@0.2.0");
}

#[test]
fn a_different_version_of_a_declared_interface_is_refused() {
    let name = "elastos:bus/runtime@2.0.0";
    let wasm = wat::parse_str(format!(r#"(component (import "{name}" (instance)))"#)).unwrap();
    for declared in [
        "elastos:bus/runtime@1.0.0",
        "elastos:bus",
        "elastos:bus/runtime",
        "elastos:bus/runtime@*",
        "elastos:bus/runtime@>=1.0.0",
        "elastos:bus/log@2.0.0",
    ] {
        assert_undeclared(&wasm, &[declared], name);
    }
}

#[test]
fn core_module_bytes_are_not_accepted_as_a_component() {
    let wasm = wat::parse_str("(module)").unwrap();
    let refusal = audit_component(&wasm, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::NotAComponent);
    assert_eq!(refusal.to_string(), "not a component");
}

#[test]
fn component_custom_section_carrying_code_is_refused() {
    for (payload, expected) in [
        (r#"\00asm\01\00\00\00"#, Err(Refusal::CodeInCustomSection)),
        (
            r#"text\00asm\01\00\00\00tail"#,
            Err(Refusal::CodeInCustomSection),
        ),
        ("plain text", Ok(vec![])),
    ] {
        let section = format!(r#"(@custom "x" "{payload}")"#);
        for source in [
            format!("(component {section})"),
            format!("(component (core module {section}))"),
            format!("(component (component {section}))"),
            format!("(component (component (core module {section})))"),
        ] {
            let wasm = wat::parse_str(&source).unwrap();
            let result = audit_component(&wasm, &[]);
            assert_eq!(result, expected, "{source}");
            if let Err(refusal) = result {
                assert_eq!(refusal.to_string(), "code in custom section");
            }
        }
    }
}

#[test]
fn invalid_component_bytes_are_refused() {
    let mut truncated =
        wat::parse_str(r#"(component (import "elastos:bus/runtime@1.0.0" (instance)))"#).unwrap();
    truncated.pop();
    let mut unknown_section = wat::parse_str("(component)").unwrap();
    unknown_section.extend_from_slice(&[42, 0]);
    for wasm in [
        // Text encoding succeeds; full validation must reject the invalid body.
        wat::parse_str("(component (core module (func (result i32))))").unwrap(),
        truncated,
        unknown_section,
        wat::parse_str(
            r#"(component
                (import "elastos:bus/runtime@1.0.0" (instance))
                (import "elastos:bus/runtime@1.0.0" (instance)))"#,
        )
        .unwrap(),
    ] {
        let refusal = audit_component(&wasm, &[]).unwrap_err();
        assert_eq!(refusal, Refusal::NotAComponent);
        assert_eq!(refusal.to_string(), "not a component");
    }
}

#[test]
fn embedded_imports_are_internal() {
    let wasm = wat::parse_str(
        r#"(component
            (core module (import "wasi_snapshot_preview1" "fd_write" (func)))
            (component
                (import "wasi:filesystem/types@0.2.0" (instance))
                (component (import "wasi:clocks/wall-clock@0.2.0" (instance))))
            (import "elastos:bus/runtime@1.0.0" (instance)))"#,
    )
    .unwrap();
    let name = "elastos:bus/runtime@1.0.0";
    assert_eq!(audit_component(&wasm, &[name]), Ok(vec![name.into()]));
    assert_undeclared(&wasm, &[], name);
}
