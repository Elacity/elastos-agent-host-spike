//! Source and admission tripwires for the current app-capsule boundary.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use elastos_server::{validate_component_imports, ALLOWED_BUS_IMPORTS};
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}

fn read(relative: &str) -> String {
    // A Windows checkout can hold CRLF text. These checks compare source
    // content, so they compare it with the one line ending the source states.
    fs::read_to_string(repo().join(relative))
        .unwrap()
        .replace("\r\n", "\n")
}

/// The repository-relative path as text with `/` separators, so a manifest
/// inventory reads the same on every platform.
fn relative_text(path: &Path) -> String {
    path.strip_prefix(repo())
        .unwrap()
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn parts(items: &[&str]) -> String {
    items.concat()
}

fn walk(dir: &Path, name: &str, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            let basename = entry.file_name();
            if basename != ".git" && basename != "target" && basename != "target-build" {
                walk(&path, name, found);
            }
        } else if kind.is_file() && entry.file_name() == name {
            found.push(path);
        }
    }
}

fn walk_rust(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            let basename = entry.file_name();
            if basename != ".git" && basename != "target" && basename != "target-build" {
                walk_rust(&path, found);
            }
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

fn strings_with_scheme(value: &Value, schemes: &[String]) -> bool {
    let names_scheme = |text: &str| {
        schemes
            .iter()
            .any(|scheme| text == scheme.trim_end_matches('/') || text.starts_with(scheme))
    };
    match value {
        Value::String(text) => names_scheme(text),
        Value::Array(items) => items.iter().any(|item| strings_with_scheme(item, schemes)),
        Value::Object(items) => items
            .iter()
            .any(|(key, item)| names_scheme(key) || strings_with_scheme(item, schemes)),
        _ => false,
    }
}

fn manifest_inventory() -> (usize, BTreeSet<String>) {
    let mut paths = Vec::new();
    walk(&repo(), "capsule.json", &mut paths);
    let schemes =
        [parts(&["n", "et"]), parts(&["ex", "it"])].map(|name| format!("elastos://{name}/"));
    let mut naming = BTreeSet::new();
    let mut providers = BTreeSet::new();
    for path in &paths {
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        if let Some(provides) = value.get("provides").and_then(Value::as_str) {
            if strings_with_scheme(&Value::String(provides.to_string()), &schemes) {
                providers.insert(relative_text(path));
            }
        }
        if strings_with_scheme(&value, &schemes) {
            naming.insert(relative_text(path));
        }
    }
    let expected_providers = [
        "capsules/net-provider/capsule.json",
        "capsules/exit-provider/capsule.json",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(providers, expected_providers, "scheme providers changed");
    (paths.len(), naming)
}

#[test]
fn row_1_manifest_resources() {
    let (scanned, naming) = manifest_inventory();
    let expected = [
        "capsules/net-provider/capsule.json",
        "capsules/exit-provider/capsule.json",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(naming, expected, "manifest resource set changed");
    println!(
        "manifests scanned={scanned}, naming net/exit={}",
        naming.len()
    );
}

fn source_list(source: &str, name: &str) -> Vec<String> {
    let declaration = format!("const {name}:");
    let start = source.find(&declaration).unwrap();
    let table = source[start..].split_once("];").unwrap().0;
    table
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn expected_bus_imports(version: &str, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|name| format!("elastos:bus/{name}@{version}"))
        .collect()
}

fn expected_core_builtins() -> Vec<String> {
    let mut pairs = Vec::new();
    for name in [
        "[backpressure-inc]",
        "[backpressure-dec]",
        "[waitable-set-new]",
        "[waitable-set-wait]",
        "[waitable-set-poll]",
        "[waitable-set-drop]",
        "[waitable-join]",
        "[thread-yield]",
        "[subtask-drop]",
        "[subtask-cancel]",
        "[context-get-0]",
        "[context-set-0]",
    ] {
        pairs.extend(["$root".to_string(), name.to_string()]);
    }
    pairs.extend(["[export]$root".to_string(), "[task-cancel]".to_string()]);
    for name in [
        "[task-return]run",
        "[stream-new-0]run",
        "[stream-cancel-read-0]run",
        "[stream-cancel-write-0]run",
        "[stream-drop-readable-0]run",
        "[stream-drop-writable-0]run",
        "[async-lower][stream-read-0]run",
        "[async-lower][stream-write-0]run",
    ] {
        pairs.extend([
            "[export]elastos:bus/lifecycle@2.0.0".to_string(),
            name.to_string(),
        ]);
    }
    pairs
}

fn expected_core_markers() -> Vec<String> {
    [
        parts(&["wa", "si"]),
        "env".to_string(),
        "preopen".to_string(),
        parts(&["sock", "et"]),
        "sock".to_string(),
        "fifo".to_string(),
        "fd_".to_string(),
        "path_".to_string(),
        parts(&["ht", "tp"]),
        "tcp".to_string(),
        "udp".to_string(),
        "ELASTOS_API".to_string(),
        "ELASTOS_TOKEN".to_string(),
        "ELASTOS_CARRIER_FIFOS".to_string(),
        "_carrier".to_string(),
    ]
    .into()
}

fn admission_inventory() -> Vec<Vec<String>> {
    let source = read("elastos/crates/elastos-server/src/component.rs");
    let core_start = source.find("fn validate_core_import(").unwrap();
    let core_end = source[core_start..].find("\n#[cfg(test)]").unwrap() + core_start;
    let core_rules = &source[core_start..core_end];
    let pinned_core_rules = r#"fn validate_core_import(
    module: &str,
    name: &str,
    allowed: &[&str],
    builtins: &[(&str, &str)],
) -> std::result::Result<(), String> {
    let lower = format!("{module}::{name}").to_ascii_lowercase();
    if FORBIDDEN_AUTHORITY_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        return Err(format!(
            "component core module import \"{module}::{name}\" is forbidden"
        ));
    }

    if builtins
        .iter()
        .any(|(builtin_module, builtin_name)| *builtin_module == module && *builtin_name == name)
    {
        return Ok(());
    }
    if allowed.contains(&module) {
        return Ok(());
    }
    if module.is_empty() && (name == "$imports" || name.bytes().all(|byte| byte.is_ascii_digit())) {
        return Ok(());
    }

    Err(format!(
        "component core module import \"{module}::{name}\" is not allowed; use elastos:bus component imports only"
    ))
}"#;
    assert_eq!(
        core_rules.trim(),
        pinned_core_rules,
        "component core import allowance rules changed"
    );
    let expected = [
        expected_bus_imports(
            "1.0.0",
            &["types", "runtime", "identity", "capabilities", "providers"],
        ),
        expected_bus_imports(
            "2.0.0",
            &[
                "types",
                "runtime",
                "identity",
                "capabilities",
                "providers",
                "clock",
                "random",
                "ui",
                "credentials",
            ],
        ),
        expected_core_builtins(),
        expected_core_markers(),
    ];
    let names = [
        "ALLOWED_BUS_IMPORTS",
        "ALLOWED_BUS_V2_IMPORTS",
        "ALLOWED_V2_CORE_BUILTINS",
        "FORBIDDEN_AUTHORITY_MARKERS",
    ];
    let counts = [5, 9, 42, 15];
    let mut actual = Vec::new();
    for ((name, pinned), count) in names.into_iter().zip(expected).zip(counts) {
        let list = source_list(&source, name);
        assert_eq!(list.len(), count, "{name} count changed");
        assert_eq!(list, pinned, "{name} content changed");
        actual.push(list);
    }
    assert_eq!(
        actual[0],
        ALLOWED_BUS_IMPORTS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "source and compiled Bus v1 admission lists differ"
    );
    actual
}

#[test]
fn row_2_component_admission() {
    let forbidden = [
        parts(&["sock", "et"]),
        parts(&["net", "work"]),
        parts(&["ht", "tp"]),
        parts(&["d", "ns"]),
        parts(&["i", "p"]),
    ];
    let lists = admission_inventory();
    for (index, list) in lists.iter().take(3).enumerate() {
        for entry in list {
            assert!(
                !forbidden
                    .iter()
                    .any(|word| entry.to_ascii_lowercase().contains(word)),
                "forbidden admission entry in list {index}: {entry}"
            );
        }
    }
    for name in [
        parts(&["wasi:", "sockets/", "tcp"]),
        parts(&["wasi:", "sockets/", "udp"]),
        parts(&["wasi:", "sockets/", "ip-name-lookup"]),
        parts(&["wasi:", "http/", "outgoing-handler"]),
    ] {
        let bytes = wat::parse_str(format!("(component (import \"{name}\" (instance)))")).unwrap();
        let error = validate_component_imports(&bytes).unwrap_err();
        assert!(error.contains(&name), "{name}: {error}");
    }
    println!(
        "admission lists=4; Bus v1={}, Bus v2={}, v2 core pairs={}, core markers={}",
        lists[0].len(),
        lists[1].len(),
        lists[2].len() / 2,
        lists[3].len()
    );
}

fn forbidden_wit_name_part(part: &str) -> bool {
    let lower = part.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "host"
            | "port"
            | "address"
            | "addr"
            | "localhost"
            | "ip"
            | "socket"
            | "ticket"
            | "dns"
            | "tcp"
            | "udp"
    ) || ["src", "dst", "peer", "remote"]
        .iter()
        .any(|prefix| lower == format!("{prefix}ip"))
}

fn check_wit(text: &str, world_name: &str, expected: &[&str]) -> Result<usize, String> {
    let world = text
        .split_once(world_name)
        .ok_or_else(|| "world missing".to_string())?
        .1;
    let body = world
        .split_once('{')
        .and_then(|(_, tail)| tail.split_once('}'))
        .ok_or_else(|| "world body missing".to_string())?
        .0;
    let imports: Vec<_> = body
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("import "))
        .map(str::trim)
        .collect();
    assert_eq!(imports, expected, "{world_name} imports changed");
    let code = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for part in code.split(|c: char| !c.is_ascii_alphanumeric()) {
        if forbidden_wit_name_part(part) {
            return Err(format!("forbidden WIT name part: {part}"));
        }
    }
    Ok(imports.len())
}

#[test]
fn row_3_wit_world() {
    let v1 = read("elastos/wit/elastos-bus-v1.wit");
    let v2 = read("elastos/wit-bus-v2/elastos-bus-v2.wit");
    let v1_count = check_wit(
        &v1,
        "world product-capsule-v1",
        &["runtime", "identity", "capabilities", "providers"],
    )
    .unwrap();
    let v2_count = check_wit(
        &v2,
        "world product-capsule-v2",
        &[
            "runtime",
            "identity",
            "capabilities",
            "providers",
            "clock",
            "random",
            "ui",
            "credentials",
        ],
    )
    .unwrap();
    println!("world imports: Bus v1={v1_count}, Bus v2={v2_count}");
}

#[test]
fn row_3_scratch_wit_when_supplied() {
    if let Ok(path) = std::env::var("M3_TRIPWIRE_SCRATCH_WIT") {
        check_wit(
            &fs::read_to_string(path).unwrap(),
            "world product-capsule-v2",
            &[
                "runtime",
                "identity",
                "capabilities",
                "providers",
                "clock",
                "random",
                "ui",
                "credentials",
            ],
        )
        .unwrap();
    }
}

#[test]
fn row_4_guest_sdk_open_inventory() {
    let mut paths = Vec::new();
    walk_rust(&repo().join("elastos/crates/elastos-guest/src"), &mut paths);
    let needles = [
        parts(&["std::", "net"]),
        parts(&["Tcp", "Stream"]),
        parts(&["Udp", "Socket"]),
        parts(&["sock", "et"]),
    ];
    let manifest = read("elastos/crates/elastos-guest/Cargo.toml");
    let manifest: toml::Value = manifest.parse().unwrap();
    fn network_deps(value: &toml::Value, found: &mut Vec<String>) {
        let Some(table) = value.as_table() else {
            return;
        };
        for (key, child) in table {
            if key == "dependencies" || key == "dev-dependencies" || key == "build-dependencies" {
                if let Some(deps) = child.as_table() {
                    for (name, spec) in deps {
                        let lower = name.to_ascii_lowercase();
                        let known =
                            ["reqwest", "hyper", "socket2", "mio"].contains(&lower.as_str());
                        let tokio_net = lower == "tokio"
                            && spec
                                .get("features")
                                .and_then(toml::Value::as_array)
                                .is_some_and(|features| {
                                    features
                                        .iter()
                                        .filter_map(toml::Value::as_str)
                                        .any(|feature| {
                                            feature.eq_ignore_ascii_case("net")
                                                || feature.eq_ignore_ascii_case("full")
                                        })
                                });
                        if known || tokio_net {
                            found.push(name.clone());
                        }
                    }
                }
            }
            network_deps(child, found);
        }
    }
    let mut dependency_hits = Vec::new();
    network_deps(&manifest, &mut dependency_hits);
    assert!(
        dependency_hits.is_empty(),
        "guest SDK network client dependency changed: {dependency_hits:?}"
    );
    let mut hits = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path).unwrap();
        for (number, line) in source.lines().enumerate() {
            for needle in &needles {
                if line
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
                {
                    hits.push(format!(
                        "{}:{}:{needle}",
                        path.file_name().unwrap().to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert_eq!(hits.len(), 7, "guest SDK inventory changed: {hits:?}");
    assert!(
        hits.iter().all(|hit| hit.starts_with("runtime.rs:")),
        "{hits:?}"
    );
    println!(
        "OPEN: guest SDK runtime.rs has {} raw-network name hits; M2 KT3 owns migration",
        hits.len()
    );
}

#[test]
fn row_5_component_linker() {
    let mut paths = Vec::new();
    walk_rust(
        &repo().join("elastos/crates/elastos-compute/src"),
        &mut paths,
    );
    paths.sort();
    let mut calls = Vec::new();
    let mut wrappers = Vec::new();
    for path in &paths {
        let source = fs::read_to_string(path).unwrap();
        for (number, line) in source.lines().enumerate() {
            let active = line.split_once("//").map_or(line, |(code, _)| code);
            if active.to_ascii_lowercase().contains(&parts(&["wa", "si"])) {
                panic!(
                    "component host added a WASI reference: {}:{}",
                    path.display(),
                    number + 1
                );
            }
            if active.contains(&parts(&["add_to_", "linker"])) {
                calls.push(format!(
                    "{}:{}:{}",
                    path.display(),
                    number + 1,
                    active.trim()
                ));
            }
            if ["func_wrap", "func_new"]
                .iter()
                .any(|needle| active.contains(needle))
            {
                wrappers.push(format!(
                    "{}:{}:{}",
                    path.display(),
                    number + 1,
                    active.trim()
                ));
            }
            for forbidden in [
                parts(&["wasi_", "sockets"]),
                parts(&["wasi_", "http"]),
                parts(&["wasi::", "sockets"]),
                parts(&["wasi::", "http"]),
                parts(&["enable_", "network"]),
            ] {
                assert!(
                    !active.contains(&forbidden),
                    "component host names {forbidden}: {}:{}",
                    path.display(),
                    number + 1
                );
            }
        }
    }
    assert_eq!(calls.len(), 2, "linker call count changed: {calls:?}");
    assert!(calls[0].contains(&parts(&["ProductCapsuleV1::", "add_to_linker"])));
    assert!(calls[1].contains(&parts(&["ProductCapsuleV2::", "add_to_linker"])));
    assert!(
        wrappers.is_empty(),
        "host function wrappers changed: {wrappers:?}"
    );
    println!(
        "component host Rust files={}; linked WASI interfaces=0; linked Bus worlds={}; host wrappers={}",
        paths.len(), calls.len(), wrappers.len()
    );
}

#[test]
fn row_6_owner_only_anchor() {
    let source = read("elastos/crates/elastos-server/src/api/handlers/provider.rs");
    let name = parts(&["review559_existing_network_", "tokens_are_owner_only"]);
    assert!(
        source.contains(&format!("async fn {name}()")),
        "owner-only test missing"
    );
}

#[test]
fn summary() {
    let (scanned, naming) = manifest_inventory();
    let v1 = read("elastos/wit/elastos-bus-v1.wit");
    let v2 = read("elastos/wit-bus-v2/elastos-bus-v2.wit");
    let lists = admission_inventory();
    println!(
        "tripwire summary: manifests scanned={scanned}, naming net/exit={}, lists={}, Bus v1 imports={}, Bus v2 imports={}",
        naming.len(),
        lists.len(),
        check_wit(&v1, "world product-capsule-v1", &["runtime", "identity", "capabilities", "providers"]).unwrap(),
        check_wit(&v2, "world product-capsule-v2", &["runtime", "identity", "capabilities", "providers", "clock", "random", "ui", "credentials"]).unwrap()
    );
}
