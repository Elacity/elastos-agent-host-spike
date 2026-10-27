use std::{fs, path::Path};
use wasm_capsule_audit::{
    audit, audit_component, memories, DeclaredImport, MemoryLimits, Refusal, AUDIT_API,
};
use wasmparser::{Parser, Payload, Validator};

fn import(module: &str, name: &str) -> DeclaredImport {
    DeclaredImport {
        module: module.into(),
        name: name.into(),
    }
}

fn assert_undeclared(wasm: &[u8], declared: &[DeclaredImport], expected: &DeclaredImport) {
    let refusal = audit(wasm, declared).expect_err("undeclared import must be refused");
    assert_eq!(
        refusal,
        Refusal::Undeclared {
            module: expected.module.clone(),
            name: expected.name.clone(),
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("undeclared import {}.{}", expected.module, expected.name)
    );
}

fn read_source(relative: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap()
}

#[test]
fn zero_import_module_passes() {
    let wasm = wat::parse_str(
        r#"(module
            (memory 1)
            (func (export "digest") (result i32)
                i32.const 0
                i32.const 0
                i32.const 1
                memory.fill
                i32.const 255
                i32.extend8_s))"#,
    )
    .unwrap();
    assert_eq!(audit(&wasm, &[]), Ok(vec![]));
}

#[test]
fn undeclared_wasi_import_is_refused_by_name() {
    let wasm =
        wat::parse_str(r#"(module (import "wasi_snapshot_preview1" "fd_write" (func)))"#).unwrap();
    assert_undeclared(&wasm, &[], &import("wasi_snapshot_preview1", "fd_write"));
}

#[test]
fn clock_random_and_socket_imports_are_refused() {
    for name in [
        "clock_time_get",
        "random_get",
        "sock_accept",
        "sock_recv",
        "sock_send",
        "sock_shutdown",
    ] {
        let wasm = wat::parse_str(format!(
            r#"(module (import "wasi_snapshot_preview1" "{name}" (func)))"#
        ))
        .unwrap();
        assert_undeclared(&wasm, &[], &import("wasi_snapshot_preview1", name));
    }
}

#[test]
fn declared_import_passes_and_only_that_one() {
    let allowed = import("env", "first");
    let declared = std::slice::from_ref(&allowed);
    let wasm = wat::parse_str(r#"(module (import "env" "first" (func)))"#).unwrap();
    assert_eq!(audit(&wasm, declared), Ok(vec![allowed.clone()]));

    let extra =
        wat::parse_str(r#"(module (import "env" "first" (func)) (import "env" "second" (func)))"#)
            .unwrap();
    assert_undeclared(&extra, declared, &import("env", "second"));

    let different = wat::parse_str(r#"(module (import "env" "second" (func)))"#).unwrap();
    assert_undeclared(&different, declared, &import("env", "second"));
    let other_module = wat::parse_str(r#"(module (import "other" "first" (func)))"#).unwrap();
    assert_undeclared(&other_module, declared, &import("other", "first"));

    // Both fields must match one declared entry.
    let pairs = [
        import("wasi_snapshot_preview1", "proc_exit"),
        import("env", "fd_write"),
    ];
    let both = wat::parse_str(
        r#"(module
            (import "wasi_snapshot_preview1" "proc_exit" (func))
            (import "env" "fd_write" (func)))"#,
    )
    .unwrap();
    assert_eq!(audit(&both, &pairs), Ok(pairs.to_vec()));
    let crossed =
        wat::parse_str(r#"(module (import "wasi_snapshot_preview1" "fd_write" (func)))"#).unwrap();
    assert_undeclared(
        &crossed,
        &pairs,
        &import("wasi_snapshot_preview1", "fd_write"),
    );

    // Each field must equal the full declared field.
    let exact_pairs = [
        import("wasi_snapshot_preview1", "fd_read"),
        import("wasi:cli/environment@0.2.0", "get-environment"),
    ];
    let exact = wat::parse_str(
        r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func))
            (import "wasi:cli/environment@0.2.0" "get-environment" (func)))"#,
    )
    .unwrap();
    assert_eq!(audit(&exact, &exact_pairs), Ok(exact_pairs.to_vec()));
    let longer_name =
        wat::parse_str(r#"(module (import "wasi_snapshot_preview1" "fd_readdir" (func)))"#)
            .unwrap();
    assert_undeclared(
        &longer_name,
        &exact_pairs,
        &import("wasi_snapshot_preview1", "fd_readdir"),
    );
    let longer_module = wat::parse_str(
        r#"(module (import "wasi:cli/environment@0.2.0-rc.1" "get-environment" (func)))"#,
    )
    .unwrap();
    assert_undeclared(
        &longer_module,
        &exact_pairs,
        &import("wasi:cli/environment@0.2.0-rc.1", "get-environment"),
    );

    // Exact matches pass; matching only a declared suffix is refused.
    let suffix_pairs = [
        import("env", "read"),
        import("wasi:cli/environment@0.2.0", "get-environment"),
    ];
    let suffix_control = wat::parse_str(
        r#"(module
            (import "env" "read" (func))
            (import "wasi:cli/environment@0.2.0" "get-environment" (func)))"#,
    )
    .unwrap();
    assert_eq!(
        audit(&suffix_control, &suffix_pairs),
        Ok(suffix_pairs.to_vec())
    );
    let name_suffix = wat::parse_str(r#"(module (import "env" "fd_read" (func)))"#).unwrap();
    assert_undeclared(&name_suffix, &suffix_pairs, &import("env", "fd_read"));
    let module_suffix = wat::parse_str(
        r#"(module (import "my-wasi:cli/environment@0.2.0" "get-environment" (func)))"#,
    )
    .unwrap();
    assert_undeclared(
        &module_suffix,
        &suffix_pairs,
        &import("my-wasi:cli/environment@0.2.0", "get-environment"),
    );

    // v1 matches the pair, regardless of the import kind, and keeps duplicates.
    let memory = wat::parse_str(r#"(module (import "env" "first" (memory 1)))"#).unwrap();
    assert_eq!(audit(&memory, declared), Ok(vec![allowed.clone()]));
    let repeated =
        wat::parse_str(r#"(module (import "env" "first" (func)) (import "env" "first" (func)))"#)
            .unwrap();
    assert_eq!(
        audit(&repeated, declared),
        Ok(vec![allowed.clone(), allowed.clone()])
    );

    let dotted = import("wasi:cli/environment@0.2.0", "a.b");
    let wasm =
        wat::parse_str(r#"(module (import "wasi:cli/environment@0.2.0" "a.b" (func)))"#).unwrap();
    assert_undeclared(&wasm, &[], &dotted);
    assert_eq!(
        audit(&wasm, std::slice::from_ref(&dotted)),
        Ok(vec![dotted.clone()])
    );
    assert_undeclared(
        &wasm,
        &[import("wasi:cli/environment@0.2.0.a", "b")],
        &dotted,
    );
}

#[test]
fn malformed_module_is_refused() {
    let mut truncated = wat::parse_str(r#"(module (import "env" "first" (func)) (func))"#).unwrap();
    truncated.pop();
    let mut unknown_section = wat::parse_str("(module)").unwrap();
    unknown_section.extend_from_slice(&[42, 0]);
    let invalid_body = wat::parse_str("(module (func (result i32)))").unwrap();
    for (label, wasm) in [
        ("random bytes", vec![0xde, 0xad, 0xbe, 0xef]),
        ("truncated body after an import", truncated),
        ("unknown section", unknown_section),
        ("Component", wat::parse_str("(component)").unwrap()),
        ("invalid function result", invalid_body),
    ] {
        let refusal = audit(&wasm, &[]).expect_err(label);
        assert_eq!(refusal, Refusal::Malformed, "{label}");
        assert_eq!(refusal.to_string(), "malformed module", "{label}");
    }
}

#[test]
fn audit_refusals_follow_the_documented_order() {
    let wasm = wat::parse_str(
        r#"(module
            (import "env" "a" (func))
            (import "env" "b" (func))
            (import "env" "c" (func)))"#,
    )
    .unwrap();
    assert_undeclared(&wasm, &[import("env", "a")], &import("env", "b"));

    // Section id, size, name length, name, then the magic in the data.
    let custom = b"\0\x09\x04note\0asm";
    let mut wasm = wat::parse_str(r#"(module (import "env" "b" (func)))"#).unwrap();
    wasm.extend_from_slice(custom);
    Validator::new().validate_all(&wasm).unwrap();
    let import_end = Parser::new(0)
        .parse_all(&wasm)
        .find_map(|payload| match payload.unwrap() {
            Payload::ImportSection(section) => Some(section.range().end),
            _ => None,
        })
        .unwrap();
    let import_end = usize::try_from(import_end).unwrap();
    assert_eq!(
        &wasm[import_end..],
        custom,
        "custom section follows imports"
    );
    let refusal = audit(&wasm, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::CodeInCustomSection);
    assert_eq!(refusal.to_string(), "code in custom section");

    let mut invalid = wat::parse_str("(module (func (result i32)))").unwrap();
    invalid.splice(8..8, custom.iter().copied());
    assert_eq!(&invalid[..8], b"\0asm\x01\0\0\0");
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
    let refusal = audit(&invalid, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::Malformed);
    assert_eq!(refusal.to_string(), "malformed module");

    // (d) The core header check precedes the custom-section check.
    let component = wat::parse_str(r#"(component (@custom "x" "\00asm"))"#).unwrap();
    Validator::new().validate_all(&component).unwrap();
    assert_eq!(
        audit_component(&component, &[]),
        Err(Refusal::CodeInCustomSection)
    );
    let refusal = audit(&component, &[]).unwrap_err();
    assert_eq!(refusal, Refusal::Malformed);
    assert_eq!(refusal.to_string(), "malformed module");
}

#[test]
fn custom_section_carrying_code_is_refused() {
    fn with_custom(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut wasm = wat::parse_str("(module)").unwrap();
        // These fixtures fit in one-byte unsigned LEB lengths.
        let size = 1 + name.len() + data.len();
        assert!(size < 128);
        wasm.extend_from_slice(&[0, size as u8, name.len() as u8]);
        wasm.extend_from_slice(name);
        wasm.extend_from_slice(data);
        wasm
    }

    assert_eq!(audit(&with_custom(b"note", b"plain text"), &[]), Ok(vec![]));
    for embedded in [
        wat::parse_str("(module)").unwrap(),
        wat::parse_str("(component)").unwrap(),
        b"\0asm".to_vec(),
    ] {
        for offset in [0, 1, 7, 16] {
            let mut payload = vec![b'x'; offset];
            payload.extend_from_slice(&embedded);
            payload.extend_from_slice(b"tail");
            let refusal = audit(&with_custom(b"note", &payload), &[]).unwrap_err();
            assert_eq!(refusal, Refusal::CodeInCustomSection);
            assert_eq!(refusal.to_string(), "code in custom section");
        }
    }
    // A partial magic sequence is plain payload, not an embedded header.
    assert_eq!(audit(&with_custom(b"note", b"\0as"), &[]), Ok(vec![]));

    for (label, name, data) in [
        (
            "module header in the name",
            b"\0asm\x01\0\0\0".as_slice(),
            b"plain text".as_slice(),
        ),
        ("magic across name and data", b"note\0a", b"sm\x01\0\0\0"),
        ("magic starts in the name length", b"", b"asm\x01\0\0\0"),
    ] {
        let result = audit(&with_custom(name, data), &[]);
        assert_eq!(result, Err(Refusal::CodeInCustomSection), "{label}");
        assert_eq!(
            result.unwrap_err().to_string(),
            "code in custom section",
            "{label}"
        );
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
        let mut wasm = wat::parse_str("(module)").unwrap();
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
        let result = audit(&wasm, &[]);
        assert_eq!(result, expected, "padded size with name {name:?}");
        if let Err(refusal) = result {
            assert_eq!(refusal.to_string(), "code in custom section");
        }
    }
}

#[test]
fn compact_import_groups_are_listed_and_refused_by_name() {
    let wasm = wat::parse_str(
        r#"(module
            (import "env" "first" (func))
            (import "wasi_snapshot_preview1" (item "fd_write" (func)) (item "random_get" (func)))
            (import "wasi_snapshot_preview1" (item "sock_send") (item "sock_recv") (func)))"#,
    )
    .unwrap();
    let expected = vec![
        import("env", "first"),
        import("wasi_snapshot_preview1", "fd_write"),
        import("wasi_snapshot_preview1", "random_get"),
        import("wasi_snapshot_preview1", "sock_send"),
        import("wasi_snapshot_preview1", "sock_recv"),
    ];
    let mut declared: Vec<_> = expected.iter().rev().cloned().collect();
    declared.push(import("env", "unused"));
    assert_eq!(audit(&wasm, &declared), Ok(expected.clone()));

    for index in [2, 4] {
        let mut declared = expected.clone();
        let missing = declared.remove(index);
        assert_undeclared(&wasm, &declared, &missing);
    }
}

#[test]
fn public_api_is_v1() {
    assert_eq!(AUDIT_API, 1);
    let audit_v1: fn(&[u8], &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> = audit;
    assert_eq!(
        audit_v1(&wat::parse_str("(module)").unwrap(), &[]),
        Ok(vec![])
    );
    let component_v1: fn(&[u8], &[&str]) -> Result<Vec<String>, Refusal> = audit_component;
    assert_eq!(
        component_v1(&wat::parse_str("(component)").unwrap(), &[]),
        Ok(vec![])
    );
    let interface = read_source("INTERFACE.md");
    for (refusal, template) in [
        (
            Refusal::Undeclared {
                module: "env".into(),
                name: "first".into(),
            },
            "undeclared import {module}.{name}",
        ),
        (Refusal::Malformed, "malformed module"),
        (Refusal::CodeInCustomSection, "code in custom section"),
        (
            Refusal::UndeclaredInterface {
                name: "first".into(),
            },
            "undeclared interface {name}",
        ),
        (Refusal::NotAComponent, "not a component"),
    ] {
        assert!(
            interface.contains(&format!("`{template}`")),
            "missing v1 string: {template}"
        );
        let documented = template
            .replace("{module}", "env")
            .replace("{name}", "first");
        assert_eq!(refusal.to_string(), documented);
        let error: &dyn std::error::Error = &refusal;
        assert_eq!(error.to_string(), documented);
    }

    let source = read_source("src/lib.rs");
    for (file, contents) in [("src/lib.rs", &source), ("INTERFACE.md", &interface)] {
        let lines: Vec<_> = contents.lines().collect();
        for (item, attributes) in [
            (
                "pub struct DeclaredImport {",
                ["#[derive(Debug, Clone, PartialEq, Eq)]"].as_slice(),
            ),
            (
                "pub struct MemoryLimits {",
                ["#[derive(Debug, Clone, PartialEq, Eq)]"].as_slice(),
            ),
            (
                "pub enum Refusal {",
                [
                    "#[derive(Debug, Clone, PartialEq, Eq)]",
                    "#[non_exhaustive]",
                ]
                .as_slice(),
            ),
        ] {
            let index = lines
                .iter()
                .position(|line| *line == item)
                .unwrap_or_else(|| panic!("{file}: expected line {item}"));
            for (offset, expected) in attributes.iter().rev().enumerate() {
                let actual = index.checked_sub(offset + 1).map(|i| lines[i]);
                assert_eq!(
                    actual,
                    Some(*expected),
                    "{file}: expected line {expected} at offset -{} from {item}",
                    offset + 1
                );
            }
        }
    }
    let prefixes = [
        "pub const AUDIT_API:",
        "pub struct DeclaredImport",
        "pub module:",
        "pub name:",
        "pub enum Refusal",
        "pub fn audit(",
        "pub fn audit_component(",
        "pub struct MemoryLimits",
        "pub minimum:",
        "pub maximum:",
        "pub memory64:",
        "pub shared:",
        "pub fn memories(",
    ];
    let public: Vec<_> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub "))
        .collect();
    for line in &public {
        assert!(
            prefixes.iter().any(|prefix| line.starts_with(prefix)),
            "unexpected public item: {line}"
        );
    }
    for prefix in prefixes {
        assert_eq!(
            public
                .iter()
                .filter(|line| line.starts_with(prefix))
                .count(),
            1,
            "expected one {prefix}"
        );
    }
    assert_eq!(
        interface
            .matches("pub fn memories(wasm: &[u8]) -> Result<Vec<MemoryLimits>, Refusal>;")
            .count(),
        1
    );
}

#[test]
fn defined_memory_reports_its_page_limits() {
    let wasm = wat::parse_str("(module (memory 16 1024) (memory 1))").unwrap();
    assert_eq!(
        memories(&wasm),
        Ok(vec![
            MemoryLimits {
                minimum: 16,
                maximum: Some(1024),
                memory64: false,
                shared: false,
            },
            MemoryLimits {
                minimum: 1,
                maximum: None,
                memory64: false,
                shared: false,
            },
        ])
    );
}

#[test]
fn memory_without_a_maximum_reports_none() {
    let empty = wat::parse_str("(module)").unwrap();
    assert_eq!(memories(&empty), Ok(vec![]));
    let wasm = wat::parse_str("(module (memory 16))").unwrap();
    assert_eq!(
        memories(&wasm),
        Ok(vec![MemoryLimits {
            minimum: 16,
            maximum: None,
            memory64: false,
            shared: false,
        }])
    );
}
