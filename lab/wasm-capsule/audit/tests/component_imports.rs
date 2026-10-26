use wasm_capsule_audit::{audit, audit_component, Refusal};
use wasmparser::{Parser, Payload, Validator};

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

    let sections = wat::parse_str(
        r#"(component
            (import "elastos:bus/runtime@1.0.0" (instance))
            (core module)
            (import "wasi:filesystem/types@0.2.0" (instance)))"#,
    )
    .unwrap();
    let both = ["wasi:filesystem/types@0.2.0", "elastos:bus/runtime@1.0.0"];
    assert_eq!(
        audit_component(&sections, &both),
        Ok(vec![both[1].into(), both[0].into()])
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

    let sections = wat::parse_str(
        r#"(component
            (import "elastos:bus/runtime@1.0.0" (instance))
            (core module)
            (import "wasi:filesystem/types@0.2.0" (instance)))"#,
    )
    .unwrap();
    assert_undeclared(
        &sections,
        &["elastos:bus/runtime@1.0.0"],
        "wasi:filesystem/types@0.2.0",
    );
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

    for (declared, name) in [
        ("elastos:bus/runtime@1.0.0", "elastos:bus/runtime@1.1.0"),
        ("elastos:bus/runtime@1.0.0", "elastos:bus/runtime@1.0.1"),
        ("elastos:bus/runtime@1.1.0", "elastos:bus/runtime@1.0.0"),
    ] {
        let wasm = wat::parse_str(format!(r#"(component (import "{name}" (instance)))"#)).unwrap();
        assert_undeclared(&wasm, &[declared], name);
    }
}

#[test]
fn component_import_names_with_options_are_refused() {
    for (name, option) in [
        ("elastos:bus/runtime@1.0.0", r#"(versionsuffix "-rc.1")"#),
        ("cache", r#"(implements "wasi:filesystem/types@0.2.0")"#),
        ("elastos:bus/runtime@1.0.0", r#"(external-id "x")"#),
    ] {
        let source = format!(r#"(component (import "{name}" {option} (instance)))"#);
        let wasm = wat::parse_str(&source).unwrap();
        let result = audit_component(&wasm, &[name]);
        assert_eq!(result, Err(Refusal::NotAComponent), "{source}");
        assert_eq!(result.unwrap_err().to_string(), "not a component");
    }

    for name in ["cache", "elastos:bus/runtime@1.0.0"] {
        let wasm = wat::parse_str(format!(r#"(component (import "{name}" (instance)))"#)).unwrap();
        assert_eq!(audit_component(&wasm, &[name]), Ok(vec![name.into()]));
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
fn component_refusals_follow_the_documented_order() {
    let wasm = wat::parse_str(
        r#"(component
            (import "elastos:bus/a@1.0.0" (instance))
            (import "elastos:bus/b@1.0.0" (instance))
            (import "elastos:bus/c@1.0.0" (instance)))"#,
    )
    .unwrap();
    assert_undeclared(&wasm, &["elastos:bus/a@1.0.0"], "elastos:bus/b@1.0.0");

    // Section id, size, name length, name, then the magic in the data.
    let custom = b"\0\x09\x04note\0asm";
    let mut wasm =
        wat::parse_str(r#"(component (import "elastos:bus/b@1.0.0" (instance)))"#).unwrap();
    wasm.extend_from_slice(custom);
    Validator::new().validate_all(&wasm).unwrap();
    let import_end = Parser::new(0)
        .parse_all(&wasm)
        .find_map(|payload| match payload.unwrap() {
            Payload::ComponentImportSection(section) => Some(section.range().end),
            _ => None,
        })
        .unwrap();
    let import_end = usize::try_from(import_end).unwrap();
    assert_eq!(
        &wasm[import_end..],
        custom,
        "custom section follows imports"
    );
    let refusal = audit_component(&wasm, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::CodeInCustomSection);
    assert_eq!(refusal.to_string(), "code in custom section");

    let mut invalid = wat::parse_str("(component (core module (func (result i32))))").unwrap();
    invalid.splice(8..8, custom.iter().copied());
    assert_eq!(&invalid[..8], b"\0asm\x0d\0\x01\0");
    assert_eq!(
        &invalid[8..8 + custom.len()],
        custom,
        "first section is custom"
    );
    let body_start = Parser::new(0)
        .parse_all(&invalid)
        .find_map(|payload| match payload.unwrap() {
            Payload::CodeSectionEntry(body) => Some(body.range().start),
            _ => None,
        })
        .unwrap();
    let body_start = usize::try_from(body_start).unwrap();
    assert!(
        body_start >= 8 + custom.len(),
        "invalid body follows custom section"
    );
    assert!(Validator::new().validate_all(&invalid).is_err());
    let refusal = audit_component(&invalid, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::NotAComponent);
    assert_eq!(refusal.to_string(), "not a component");

    // (d) The Component encoding check precedes the custom-section check.
    let module = wat::parse_str(r#"(module (@custom "x" "\00asm"))"#).unwrap();
    Validator::new().validate_all(&module).unwrap();
    assert_eq!(audit(&module, &[]), Err(Refusal::CodeInCustomSection));
    let refusal = audit_component(&module, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::NotAComponent);
    assert_eq!(refusal.to_string(), "not a component");
}

#[test]
fn component_custom_section_carrying_code_is_refused() {
    for (name, data, expected) in [
        (
            "x",
            r#"\00asm\01\00\00\00"#,
            Err(Refusal::CodeInCustomSection),
        ),
        (
            "x",
            r#"text\00asm\01\00\00\00tail"#,
            Err(Refusal::CodeInCustomSection),
        ),
        (
            r#"\00asm\01\00\00\00"#,
            "plain text",
            Err(Refusal::CodeInCustomSection),
        ),
        ("x", "plain text", Ok(vec![])),
    ] {
        let section = format!(r#"(@custom "{name}" "{data}")"#);
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

    let mut hidden_name = vec![
        0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01,
        0x00, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
    ];
    hidden_name.extend_from_slice(&[b'x'; 75]);
    for (name, expected) in [
        (hidden_name, Err(Refusal::CodeInCustomSection)),
        (vec![b'x'; 97], Ok(vec![])),
    ] {
        assert_eq!(name.len(), 97);
        let mut wasm = wat::parse_str("(component)").unwrap();
        let size_last_byte = wasm.len() + 2;
        // Section id, padded size 98, name length 97, then the name; data is empty.
        wasm.extend_from_slice(&[0x00, 0xe2, 0x00, 0x61]);
        wasm.extend_from_slice(&name);
        Validator::new().validate_all(&wasm).unwrap();
        if expected.is_err() {
            assert_eq!(
                &wasm[size_last_byte..size_last_byte + 24],
                wat::parse_str("(module (func))").unwrap()
            );
        }
        let result = audit_component(&wasm, &[]);
        assert_eq!(result, expected, "padded size with name {name:?}");
        if let Err(refusal) = result {
            assert_eq!(refusal.to_string(), "code in custom section");
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
