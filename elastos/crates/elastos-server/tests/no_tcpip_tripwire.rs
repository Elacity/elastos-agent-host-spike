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
    fs::read_to_string(repo().join(relative)).unwrap()
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
                providers.insert(path.strip_prefix(repo()).unwrap().display().to_string());
            }
        }
        if strings_with_scheme(&value, &schemes) {
            naming.insert(path.strip_prefix(repo()).unwrap().display().to_string());
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

fn source_bus_imports() -> Vec<String> {
    let source = read("elastos/crates/elastos-server/src/component.rs");
    let start = source
        .find(&parts(&["pub const ALLOWED_", "BUS_IMPORTS: &[&str] = &["]))
        .unwrap();
    let table = source[start..].split_once("];").unwrap().0;
    table
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"'))
        .map(|line| line.split_once('"').unwrap().0.to_string())
        .collect()
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
    let source_imports = source_bus_imports();
    assert_eq!(
        source_imports,
        ALLOWED_BUS_IMPORTS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "source and compiled admission lists differ"
    );
    for import in ALLOWED_BUS_IMPORTS {
        assert!(
            !forbidden
                .iter()
                .any(|word| import.to_lowercase().contains(word)),
            "forbidden admission interface: {import}"
        );
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
    println!("allowed imports={}", ALLOWED_BUS_IMPORTS.len());
}

fn check_wit(text: &str) -> Result<usize, String> {
    let world_name = parts(&["world product-", "capsule-v2"]);
    let world = text
        .split_once(&world_name)
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
    assert_eq!(
        imports,
        [
            "runtime",
            "identity",
            "capabilities",
            "providers",
            "clock",
            "random",
            "ui",
            "credentials"
        ],
        "world imports changed"
    );
    let forbidden = [
        parts(&["ho", "st"]),
        parts(&["po", "rt"]),
        parts(&["add", "ress"]),
        parts(&["i", "p"]),
        parts(&["sock", "et"]),
        parts(&["tick", "et"]),
        parts(&["d", "ns"]),
        parts(&["t", "cp"]),
        parts(&["u", "dp"]),
    ];
    let code = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for token in code.split(|c: char| !c.is_ascii_alphanumeric()) {
        if forbidden
            .iter()
            .any(|word| token.to_ascii_lowercase().starts_with(word))
        {
            return Err(format!("forbidden WIT name: {token}"));
        }
    }
    Ok(imports.len())
}

#[test]
fn row_3_wit_world() {
    let text = read("elastos/wit-bus-v2/elastos-bus-v2.wit");
    let count = check_wit(&text).unwrap();
    println!("world imports={count}; resource-uri names a Runtime-routed elastos resource");
}

#[test]
fn row_3_scratch_wit_when_supplied() {
    if let Ok(path) = std::env::var("M3_TRIPWIRE_SCRATCH_WIT") {
        check_wit(&fs::read_to_string(path).unwrap()).unwrap();
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
    assert!(
        !manifest.contains(&parts(&["sock", "et"])),
        "guest SDK dependency list changed"
    );
    let mut hits = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path).unwrap();
        for (number, line) in source.lines().enumerate() {
            for needle in &needles {
                if line.contains(needle) {
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
    let source = read("elastos/crates/elastos-compute/src/providers/component.rs");
    let active = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !active.to_ascii_lowercase().contains(&parts(&["wa", "si"])),
        "component host added a WASI reference"
    );
    let calls: Vec<_> = active
        .lines()
        .filter(|line| line.contains(&parts(&["add_to_", "linker"])))
        .map(str::trim)
        .collect();
    assert_eq!(calls.len(), 2, "linker call count changed: {calls:?}");
    assert!(calls[0].contains(&parts(&["ProductCapsuleV1::", "add_to_linker"])));
    assert!(calls[1].contains(&parts(&["ProductCapsuleV2::", "add_to_linker"])));
    for forbidden in [
        parts(&["wasi_", "sockets"]),
        parts(&["wasi_", "http"]),
        parts(&["wasi::", "sockets"]),
        parts(&["wasi::", "http"]),
        parts(&["enable_", "network"]),
    ] {
        assert!(
            !active.contains(&forbidden),
            "component host names {forbidden}"
        );
    }
    println!("linked WASI interfaces=0; linked Bus worlds=2");
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
    let world = read("elastos/wit-bus-v2/elastos-bus-v2.wit");
    println!(
        "tripwire summary: manifests scanned={scanned}, naming net/exit={}, allowed imports={}, world imports={}",
        naming.len(), ALLOWED_BUS_IMPORTS.len(), check_wit(&world).unwrap()
    );
}
