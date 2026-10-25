use std::{fs, path::Path};
use wasm_capsule_audit::{audit, DeclaredImport, Refusal, AUDIT_API};

fn read_source(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: cannot read file: {error}", path.display()))
}

fn manifest_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source.lines().enumerate().filter_map(|(index, line)| {
        let line = line.trim();
        (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line))
    })
}

#[test]
fn manifest_pins_only_wasmparser_and_wat_exactly() {
    let source = read_source("Cargo.toml");
    // Recognise only this manifest's simple spelling. In particular, alternate
    // dependency tables, dotted keys and inline tables fail instead of hiding
    // an entry from a partial TOML parser.
    let mut remaining = vec![
        ("[package]", "name", "\"wasm-capsule-audit\""),
        ("[package]", "version", "\"0.1.0\""),
        ("[package]", "edition", "\"2021\""),
        ("[package]", "publish", "false"),
        ("[dependencies]", "wasmparser", "\"=0.258.0\""),
        ("[dev-dependencies]", "wat", "\"=1.258.0\""),
    ];
    let mut tables = Vec::new();
    let mut table = "";
    for (number, line) in manifest_lines(&source) {
        if line.starts_with('[') {
            assert!(
                ["[package]", "[dependencies]", "[dev-dependencies]"].contains(&line),
                "Cargo.toml:{number}: unexpected table or unsupported syntax: {line}"
            );
            assert!(
                !tables.contains(&line),
                "Cargo.toml:{number}: repeated table {line}"
            );
            tables.push(line);
            table = line;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("Cargo.toml:{number}: unsupported entry in {table}: {line}"));
        let entry = (table, key.trim(), value.trim());
        let index = remaining
            .iter()
            .position(|expected| *expected == entry)
            .unwrap_or_else(|| {
                panic!(
                    "Cargo.toml:{number}: unexpected or repeated entry {line} in {table}; \
                     expected exact package fields, wasmparser = \"=0.258.0\" in \
                     [dependencies] and wat = \"=1.258.0\" in [dev-dependencies]"
                )
            });
        remaining.remove(index);
    }
    assert!(
        remaining.is_empty(),
        "Cargo.toml: missing required entries: {remaining:?}"
    );
}

fn is_bare_path(text: &str) -> bool {
    text.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn is_plain_string(text: &str) -> bool {
    text.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .is_some_and(|inner| !inner.contains(['"', '\\', '\n', '\r']))
}

#[test]
fn manifest_has_no_workspace_table() {
    let source = read_source("Cargo.toml");
    for (number, line) in manifest_lines(&source) {
        if line.starts_with('[') {
            let table = line
                .strip_prefix('[')
                .and_then(|text| text.strip_suffix(']'))
                .unwrap_or_else(|| panic!("Cargo.toml:{number}: unsupported table: {line}"))
                .trim();
            assert!(
                is_bare_path(table),
                "Cargo.toml:{number}: unsupported table syntax: {line}"
            );
            assert!(
                table.split('.').next() != Some("workspace"),
                "Cargo.toml:{number}: workspace table {line} belongs to the lab root"
            );
        } else {
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("Cargo.toml:{number}: unsupported entry: {line}"));
            let key = key.trim();
            assert!(
                is_bare_path(key),
                "Cargo.toml:{number}: unsupported key syntax: {key}"
            );
            assert!(
                !key.split('.').any(|part| part == "workspace"),
                "Cargo.toml:{number}: workspace key {key} belongs to the lab root"
            );
            let value = value.trim();
            assert!(
                matches!(value, "true" | "false") || is_plain_string(value),
                "Cargo.toml:{number}: unsupported value for {key}: {value}"
            );
        }
    }
}

#[test]
fn lib_holds_only_the_v1_signature_with_no_logic() {
    assert_eq!(AUDIT_API, 1, "src/lib.rs: AUDIT_API must be 1");
    let audit_v1: fn(&[u8], &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> = audit;
    let declared = DeclaredImport {
        module: "elastos:bus".into(),
        name: "call".into(),
    };
    let _refusals = [
        Refusal::Undeclared {
            module: declared.module.clone(),
            name: declared.name.clone(),
        },
        Refusal::Malformed,
        Refusal::CodeInCustomSection,
    ];

    let source = read_source("src/lib.rs");
    let signature =
        "pub fn audit(wasm: &[u8], declared: &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> {";
    let public: Vec<_> = source
        .lines()
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public,
        [
            "pub const AUDIT_API: u32 = 1;",
            "pub struct DeclaredImport {",
            "pub enum Refusal {",
            signature,
        ],
        "src/lib.rs: expected exactly the four v1 public items in rustfmt form"
    );
    assert!(
        !source.contains("wasmparser"),
        "src/lib.rs: the skeleton must leave wasmparser use to cwa-001"
    );

    let (declarations, tail) = source
        .split_once(signature)
        .expect("src/lib.rs: missing the v1 audit signature");
    let declarations: String = declarations
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .flat_map(|line| line.chars().filter(|ch| !ch.is_whitespace()))
        .collect();
    assert_eq!(
        declarations,
        concat!(
            "pubconstAUDIT_API:u32=1;",
            "#[derive(Debug,Clone,PartialEq,Eq)]",
            "pubstructDeclaredImport{pubmodule:String,pubname:String,}",
            "#[derive(Debug,Clone,PartialEq,Eq)]#[non_exhaustive]",
            "pubenumRefusal{Undeclared{module:String,name:String},Malformed,CodeInCustomSection,}",
            "#[allow(unused_variables)]"
        ),
        "src/lib.rs: declarations must contain only the v1 types, derives and attributes"
    );
    let body = tail
        .trim()
        .strip_suffix('}')
        .expect("src/lib.rs: audit must end with its closing brace")
        .trim();
    let call = body.strip_suffix(';').unwrap_or(body).trim();
    let message = call
        .strip_prefix("unimplemented!(")
        .or_else(|| call.strip_prefix("todo!("))
        .and_then(|text| text.strip_suffix(')'))
        .expect("src/lib.rs: audit body must be one unimplemented! or todo! call")
        .trim();
    assert!(
        is_plain_string(message),
        "src/lib.rs: audit must contain only a literal panic message, found {body}"
    );

    let empty_core_module = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let panic = std::panic::catch_unwind(|| audit_v1(&empty_core_module, &[]))
        .expect_err("src/lib.rs: skeleton audit must panic instead of returning Ok or Err");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("src/lib.rs: audit panic must carry a text message");
    assert!(
        message.contains("cwa-001"),
        "src/lib.rs: audit panic must name cwa-001, found {message:?}"
    );
}
