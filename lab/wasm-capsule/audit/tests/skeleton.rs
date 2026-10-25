use std::{fs, path::Path};

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
