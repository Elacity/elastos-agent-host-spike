//! Count the two current capsule call layers. These rows record the source
//! contract; they do not freeze the Bus or approve a provider.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
struct Token {
    value: String,
    quoted: bool,
}

fn tokens(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
        } else if bytes[i..].starts_with(b"//") {
            i = bytes[i..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |n| i + n);
        } else if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    break;
                } else {
                    i += 1;
                }
            }
            out.push(Token {
                value: source[start..i].to_owned(),
                quoted: true,
            });
            i = (i + 1).min(bytes.len());
        } else if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push(Token {
                value: source[start..i].to_owned(),
                quoted: false,
            });
        } else {
            let value = if bytes[i..].starts_with(b"=>") {
                i += 2;
                "=>"
            } else {
                let start = i;
                i += 1;
                &source[start..i]
            };
            out.push(Token {
                value: value.to_owned(),
                quoted: false,
            });
        }
    }
    out
}

fn enclosed<'a>(input: &'a [Token], open: usize, left: &str, right: &str) -> &'a [Token] {
    assert_eq!(input[open].value, left);
    let mut depth = 0;
    for (i, token) in input.iter().enumerate().skip(open) {
        if token.value == left {
            depth += 1;
        } else if token.value == right {
            depth -= 1;
            if depth == 0 {
                return &input[open + 1..i];
            }
        }
    }
    panic!("unclosed source group at token {open}");
}

fn function_body<'a>(input: &'a [Token], name: &str) -> &'a [Token] {
    let start = input
        .windows(2)
        .position(|pair| pair[0].value == "fn" && pair[1].value == name)
        .unwrap_or_else(|| panic!("missing function {name}"));
    let open = (start + 2..input.len())
        .find(|i| input[*i].value == "{")
        .unwrap();
    enclosed(input, open, "{", "}")
}

fn quoted(input: &[Token]) -> BTreeSet<String> {
    input
        .iter()
        .filter(|token| token.quoted)
        .map(|token| token.value.clone())
        .collect()
}

fn source_tokens(file: &str) -> Vec<Token> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    tokens(&fs::read_to_string(path).unwrap())
}

fn localhost_operations(input: &[Token]) -> BTreeSet<String> {
    let name = ["LOCALHOST", "OPERATIONS"].join("_");
    let start = input.iter().position(|token| token.value == name).unwrap();
    let equals = (start..input.len())
        .find(|i| input[*i].value == "=")
        .unwrap();
    let open = (equals..input.len())
        .find(|i| input[*i].value == "[")
        .unwrap();
    let table = enclosed(input, open, "[", "]");
    let row_ctor = ["localhost", "op"].join("_");
    table
        .windows(3)
        .filter(|part| part[0].value == row_ctor && part[1].value == "(" && part[2].quoted)
        .map(|part| part[2].value.clone())
        .collect()
}

fn scheme_arms(body: &[Token]) -> Vec<(&[Token], &[Token])> {
    let open = body
        .windows(3)
        .position(|part| {
            part[0].value == "match" && part[1].value == "scheme" && part[2].value == "{"
        })
        .map(|i| i + 2)
        .unwrap();
    let input = enclosed(body, open, "{", "}");
    let mut arms = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    for (i, token) in input.iter().enumerate() {
        match token.value.as_str() {
            "{" | "(" | "[" => depth += 1,
            "}" | ")" | "]" => {
                depth -= 1;
                // Rust permits a block arm without a trailing comma.
                if token.value == "}"
                    && depth == 0
                    && input
                        .get(i + 1)
                        .is_some_and(|next| next.quoted || next.value == "_")
                {
                    let arm = &input[start..=i];
                    if let Some(arrow) = arm.iter().position(|item| item.value == "=>") {
                        arms.push((&arm[..arrow], &arm[arrow + 1..]));
                    }
                    start = i + 1;
                }
            }
            "," if depth == 0 => {
                let arm = &input[start..i];
                if let Some(arrow) = arm.iter().position(|token| token.value == "=>") {
                    arms.push((&arm[..arrow], &arm[arrow + 1..]));
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    arms
}

fn mapped_pairs() -> BTreeMap<String, BTreeSet<String>> {
    let source = source_tokens("provider_resource.rs");
    let map_name = ["provider", "operation", "action"].join("_");
    let body = function_body(&source, &map_name);
    let mut result = BTreeMap::new();
    for (pattern, action) in scheme_arms(body) {
        let schemes = quoted(pattern);
        if schemes.is_empty() {
            continue;
        }
        let helper = action
            .windows(2)
            .find(|part| part[0].value.ends_with("_action") && part[1].value == "(")
            .map(|part| part[0].value.as_str());
        let localhost_helper = ["localhost", "op", "required", "action"].join("_");
        let mut ops = match helper {
            Some(name) if name == localhost_helper => localhost_operations(&source),
            Some(name) => quoted(function_body(&source, name)),
            None => quoted(action),
        };
        ops.extend(quoted(action));
        assert!(
            !ops.is_empty(),
            "mapping arm has no operations: {schemes:?}"
        );
        for scheme in schemes {
            assert!(result.insert(scheme, ops.clone()).is_none());
        }
    }
    result
}

fn manifests() -> BTreeMap<String, BTreeSet<String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../capsules");
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path().join("capsule.json");
        if !path.is_file() {
            continue;
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if manifest["role"] != "provider" || manifest["author"] != "elastos" {
            continue;
        }
        let Some(capabilities) = manifest
            .pointer("/authority/capabilities")
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        let Some(provides) = manifest.get("provides").and_then(|v| v.as_str()) else {
            continue;
        };
        let scheme = if let Some(rest) = provides.strip_prefix("elastos://") {
            rest.split('/').next().unwrap().to_owned()
        } else if provides.starts_with("localhost://WebSpaces/") {
            "webspace".to_owned()
        } else {
            panic!("unknown first-party provider scheme in {}", path.display());
        };
        let ops = result.entry(scheme).or_default();
        for capability in capabilities {
            for op in capability["operations"].as_array().unwrap() {
                ops.insert(op.as_str().unwrap().to_owned());
            }
        }
    }
    result
}

fn pairs(table: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<(String, String)> {
    table
        .iter()
        .flat_map(|(scheme, ops)| ops.iter().map(|op| (scheme.clone(), op.clone())))
        .collect()
}

fn print_table(table: &BTreeMap<String, BTreeSet<String>>) {
    for (scheme, ops) in table {
        println!("{scheme}: {}", ops.len());
    }
    println!(
        "TOTAL: {} schemes, {} pairs",
        table.len(),
        pairs(table).len()
    );
}

/// Layer 1 is the fixed interface layer a capsule imports. Exact names have
/// their existing admission tests; this row counts world imports and entries.
#[test]
fn layer_1_interface_counts() {
    let wit = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../wit-bus-v2/elastos-bus-v2.wit"),
    )
    .unwrap();
    let world_head = ["world product", "-capsule-v2 {"].concat();
    let world = wit
        .split(&world_head)
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    let world_count = world.split("import ").skip(1).count();
    let source = source_tokens("component.rs");
    let list_name = ["ALLOWED", "BUS", "V2", "IMPORTS"].join("_");
    let start = source
        .iter()
        .position(|token| token.value == list_name)
        .unwrap();
    let equals = (start..source.len())
        .find(|i| source[*i].value == "=")
        .unwrap();
    let open = (equals..source.len())
        .find(|i| source[*i].value == "[")
        .unwrap();
    let admitted_count = quoted(enclosed(&source, open, "[", "]")).len();
    println!("layer 1: world imports {world_count}, admission entries {admitted_count}");
    assert_eq!(world_count, 8);
    assert_eq!(admitted_count, 9);
}

/// Layer 2 counts Runtime-owned operation groups reached through typed invoke.
/// The pairs come from the action map and its helpers at test run time.
#[test]
fn layer_2_runtime_owned_counts() {
    let table = mapped_pairs();
    print_table(&table);
    let expected: BTreeMap<&str, usize> = [
        ("availability", 2),
        ("block-graph", 3),
        ("browser-engine", 10),
        ("chain", 19),
        ("content", 6),
        ("decrypt", 9),
        ("did", 14),
        ("drm", 9),
        ("exit", 6),
        ("inspect", 6),
        ("ipfs", 12),
        ("key", 9),
        ("launch", 3),
        ("localhost", 9),
        ("model", 5),
        ("net", 5),
        ("object", 26),
        ("operator-drive-adapter", 4),
        ("peer", 13),
        ("rights", 9),
        ("tunnel", 4),
        ("wallet", 1),
        ("webspace", 9),
    ]
    .into();
    assert_eq!(
        table
            .iter()
            .map(|(s, o)| (s.as_str(), o.len()))
            .collect::<BTreeMap<_, _>>(),
        expected
    );
    assert_eq!(pairs(&table).len(), 193);
}

/// OPEN (P2-3 and P2-10): report both directions of manifest/action drift.
#[test]
fn declared_versus_mapped_open() {
    let declared = pairs(&manifests());
    let mapped = pairs(&mapped_pairs());
    let declared_only: Vec<_> = declared.difference(&mapped).collect();
    let mapped_only: Vec<_> = mapped.difference(&declared).collect();
    println!(
        "OPEN declared-only {}: {declared_only:?}",
        declared_only.len()
    );
    println!("OPEN mapped-only {}: {mapped_only:?}", mapped_only.len());
    assert_eq!(declared_only.len(), 0);
    assert_eq!(mapped_only.len(), 78);
}

fn is_file_operation(scheme: &str, op: &str) -> bool {
    match scheme {
        "localhost" | "webspace" => op != "ping",
        "object" => !matches!(op, "status" | "events" | "buy" | "list_runtime_custody"),
        "content" => op != "status",
        "ipfs" => !matches!(op, "status" | "health"),
        "block-graph" | "operator-drive-adapter" => op != "status",
        "launch" => true,
        _ => false,
    }
}

/// Rong's WebSpace-files question: count file operations against every other
/// Runtime-owned pair. This is a measured share, not an ABI decision.
#[test]
fn file_operations_first() {
    let all = pairs(&mapped_pairs());
    let file: Vec<_> = all
        .iter()
        .filter(|(scheme, op)| is_file_operation(scheme, op))
        .collect();
    println!(
        "file operations {} / {}; other {}",
        file.len(),
        all.len(),
        all.len() - file.len()
    );
    assert_eq!(file.len(), 61);
    assert_eq!(all.len() - file.len(), 132);
}

/// OPEN (P2-10): today the proxy refuses a scheme/operation without a Runtime
/// action mapping. A signed third-party manifest plus user approval should
/// admit its DID-addressed pair with no Runtime source edit. A signature only
/// admits bytes; the user's grant supplies authority; a built-in scheme stays
/// owned by its existing provider.
#[test]
fn third_party_operation_open() {
    let map = mapped_pairs();
    let first_party = manifests();
    let internal = ["localhost", "launch", "content", "inspect", "peer"];
    for scheme in map.keys() {
        assert!(
            first_party.contains_key(scheme) || internal.contains(&scheme.as_str()),
            "unclassified mapped scheme: {scheme}"
        );
    }
    let raw = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider_resource.rs"),
    )
    .unwrap();
    let raw_tokens = tokens(&raw);
    let body = function_body(&raw_tokens, &["provider", "operation", "action"].join("_"));
    for needle in [
        ["nep", "tune"].concat(),
        ["third", "party"].join("_"),
        ["stand", "in"].join("_"),
    ] {
        assert!(
            !quoted(body).contains(&needle),
            "third-party scheme entered Runtime map: {needle}"
        );
    }
    let proxy = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/handlers/provider.rs"),
    )
    .unwrap();
    let action = ["provider", "operation", "action"].join("_");
    let refusal = ["Unsupported provider operation", "action mapping"].join(" ");
    let map_pos = proxy.find(&action).unwrap();
    assert!(proxy[map_pos..].contains(&refusal));
    println!("OPEN P2-10: proxy refuses an unmapped operation before provider dispatch");
}

fn is_network_verb(scheme: &str, op: &str) -> bool {
    (op == "connect" && scheme != "peer")
        || op == "stream"
        || op == "http"
        || matches!(op, "open_stream" | "close_stream")
        || op.starts_with("http_")
        || op == "discover_remote_carrier_exits"
        || (scheme == "net" && op == "resolve")
}

/// Network-locator verbs belong to the Runtime's Net and Exit providers.
/// DID and WebSpace `resolve` name identities and files, so they are separate.
#[test]
fn network_verbs_stay_with_network_providers() {
    let network: Vec<_> = pairs(&mapped_pairs())
        .into_iter()
        .filter(|(scheme, op)| is_network_verb(scheme, op))
        .collect();
    println!("network verbs {}: {network:?}", network.len());
    for (scheme, op) in &network {
        assert!(
            scheme == "net" || scheme == "exit",
            "network verb elsewhere: {scheme}/{op}"
        );
    }
    assert_eq!(network.len(), 8);
}
