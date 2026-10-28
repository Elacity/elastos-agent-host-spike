//! One check of `DISCOVERY.md` against this tree.
//!
//! The check reads files only: it loads no component, starts no activation and
//! calls no provider. A disagreement means the record is stale; updating it is
//! a later task.

use std::fs;
use std::path::{Path, PathBuf};

const RECORD_STALE: &str =
    "the record is stale; this task does not start activations. Updating the record to \
     match a newly present bridge entry, component hash, or agent-host component is a \
     later task.";

const RECORD_PATH: &str = "lab/two-capsule-run/DISCOVERY.md";
const LOG_PATH: &str = "lab/wasm-capsule/LOG.md";
const BRIDGE_PATH: &str = "lab/agent-conformance/standin-runtime/mod.rs";
const AGENT_HOST_SRC: &str = "examples/agent-host/src/lib.rs";
const AGENT_HOST_MANIFEST: &str = "examples/agent-host/capsule.json";
const AGENT_HOST_BUILD: &str = "examples/agent-host/build.sh";
const FALSIFY_PATH: &str = "examples/agent-host/falsify.py";

const LIFECYCLE_MARKER: &str = "impl exports::elastos::bus::lifecycle::Guest for AgentHost";
const RUN_MARKER: &str = "fn run() -> Result<(), elastos::bus::types::BusError>";
const EXPORT_MARKER: &str = "export!(AgentHost)";

/// The record claims this test checks. A missing claim is a stale record.
const REQUIRED_PROSE: [&str; 10] = [
    "lab stand-in, not admission",
    "two concurrent bounded activations",
    "no A3 credit",
    "no resident credit",
    "binds an instance to its component hash",
    "not the component target",
    "not the A3 target",
    "scripts/build-component-capsule.sh",
    "unverified",
    "last matching line",
];

struct Observed {
    component_sha256: String,
    core_module_cid: String,
    bridge_entry: String,
    agent_host_component: String,
    agent_host_world: String,
    agent_host_entrypoint: String,
    agent_host_build: String,
    agent_host_lifecycle_entry: String,
    agent_host_run: String,
    agent_host_export: String,
    falsify_command: String,
}

fn repo_root() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).expect("repository root")
}

fn read(repo: &Path, relative: &str) -> Result<String, String> {
    fs::read_to_string(repo.join(relative)).map_err(|err| format!("{relative}: {err}"))
}

fn record_field<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    record.lines().find_map(|line| {
        let (found, value) = line.split_once(':')?;
        (found.trim() == key).then(|| value.trim())
    })
}

/// The last matching LOG line wins because the LOG is append-only. A line
/// with two distinct 64-digit hex values is ambiguous, so the record cannot
/// name one component.
fn component_digest(log: &str) -> String {
    let mut last: Option<String> = None;
    for line in log.lines() {
        if !line.to_ascii_lowercase().contains("component") {
            continue;
        }
        let tokens = hex_tokens(line, 64);
        if tokens.is_empty() {
            continue;
        }
        let mut distinct = tokens
            .iter()
            .map(|token| token.to_ascii_lowercase())
            .collect::<Vec<_>>();
        distinct.sort_unstable();
        distinct.dedup();
        last = Some(if distinct.len() == 1 {
            distinct.remove(0)
        } else {
            "ambiguous".to_string()
        });
    }
    last.unwrap_or_else(|| "unpublished".to_string())
}

fn lab_cid(log: &str) -> String {
    const PREFIX: &str = "lab-cid:sha256:";
    for line in log.lines() {
        let Some(start) = line.find(PREFIX) else {
            continue;
        };
        let rest = &line[start + PREFIX.len()..];
        let digest = rest
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect::<String>();
        if digest.len() == 64 {
            return format!("{PREFIX}{digest}");
        }
    }
    "absent".to_string()
}

fn hex_tokens(line: &str, len: usize) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        if index - start == len {
            tokens.push(&line[start..index]);
        }
    }
    tokens
}

/// A bridge entry is a public, synchronous `StandIn` method with the
/// `BridgeHostcall` shape: `(&str, &str, Option<&str>) -> Result<String, String>`.
fn bridge_entry(source: &str) -> String {
    let mut entries: Vec<String> = Vec::new();
    let mut in_impl = false;
    let mut collecting = false;
    let mut signature = String::new();
    for line in source.lines() {
        if !in_impl {
            if line.trim_end() == "impl StandIn {" {
                in_impl = true;
            }
            continue;
        }
        if line == "}" {
            in_impl = false;
            continue;
        }
        if !collecting {
            if let Some(rest) = line.strip_prefix("    pub fn ") {
                signature.clear();
                signature.push_str("pub fn ");
                signature.push_str(rest);
                collecting = true;
            }
        } else {
            signature.push(' ');
            signature.push_str(line.trim());
        }
        if collecting && signature.contains('{') {
            if let Some(name) = bridge_shaped(&signature) {
                entries.push(name);
            }
            collecting = false;
        }
    }
    match entries.len() {
        0 => "none".to_string(),
        1 => entries.remove(0),
        _ => format!("ambiguous ({})", entries.join(", ")),
    }
}

fn bridge_shaped(signature: &str) -> Option<String> {
    let after = signature.strip_prefix("pub fn ")?;
    let open = after.find('(')?;
    let name = after[..open].trim();
    if name.is_empty() {
        return None;
    }
    let close = matching_paren(after, open)?;
    let parameters = split_parameters(&after[open + 1..close]);
    let types = parameters
        .iter()
        .map(|param| param_type(param))
        .collect::<Vec<_>>();
    let receiver = types.first().map(String::as_str);
    if receiver != Some("&self") && receiver != Some("&mutself") {
        return None;
    }
    if types.len() != 4 || types[1] != "&str" || types[2] != "&str" || types[3] != "Option<&str>" {
        return None;
    }
    let rest = after[close + 1..].trim();
    let returned = rest.strip_prefix("->")?.trim().trim_end_matches('{').trim();
    let returned = normalize_type(returned);
    (returned == "Result<String,String>").then(|| name.to_string())
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in text[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_parameters(parameters: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut parens = 0i32;
    let mut angles = 0i32;
    for (index, character) in parameters.char_indices() {
        match character {
            '(' => parens += 1,
            ')' => parens -= 1,
            '<' => angles += 1,
            '>' => angles -= 1,
            ',' if parens == 0 && angles == 0 => {
                parts.push(parameters[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let tail = parameters[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

fn param_type(parameter: &str) -> String {
    let compact: String = parameter.chars().filter(|c| !c.is_whitespace()).collect();
    if compact == "&self" || compact == "&mutself" {
        return compact;
    }
    match compact.split_once(':') {
        Some((_, kind)) => kind.to_string(),
        None => compact,
    }
}

fn normalize_type(text: &str) -> String {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.replace("std::result::Result", "Result")
}

fn declared_world(source: &str) -> Option<String> {
    let start = source.find("world:")? + "world:".len();
    let rest = &source[start..];
    let quote = rest.find('"')?;
    let rest = &rest[quote + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let rest = &rest[rest.find(':')? + 1..];
    let rest = &rest[rest.find('"')? + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn marker(source: &str, marker: &str) -> String {
    if source.contains(marker) {
        marker.to_string()
    } else {
        "absent".to_string()
    }
}

fn falsify_command(source: &str) -> String {
    let mut in_table = false;
    for line in source.lines() {
        if line.starts_with("PROVIDER_CRATES = {") {
            in_table = true;
            continue;
        }
        if in_table && line.starts_with('}') {
            break;
        }
        if !in_table {
            continue;
        }
        if line.contains("two-capsule-run") && line.contains("Cargo.toml") {
            if let Some((key, _)) = line.split_once(':') {
                return key.trim().trim_matches('"').to_string();
            }
        }
    }
    "absent".to_string()
}

/// A component binary starts with `\0asm` and the component-model version;
/// a core module uses the core version and is not a component.
fn component_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[..4] == b"\0asm" && bytes[4..8] == [0x0d, 0x00, 0x01, 0x00]
}

fn sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn observe(repo: &Path) -> Result<Observed, String> {
    let log = read(repo, LOG_PATH)?;
    let bridge_source = read(repo, BRIDGE_PATH)?;
    let agent_source = read(repo, AGENT_HOST_SRC)?;
    let manifest = read(repo, AGENT_HOST_MANIFEST)?;
    let build = read(repo, AGENT_HOST_BUILD)?;
    let falsify_source = read(repo, FALSIFY_PATH)?;

    let entrypoint = json_string(&manifest, "entrypoint")
        .ok_or_else(|| format!("{AGENT_HOST_MANIFEST} has no entrypoint"))?;
    let artifact = repo.join("examples/agent-host").join(&entrypoint);
    let agent_host_component = if artifact.is_file() {
        let bytes = fs::read(&artifact).map_err(|err| format!("{}: {err}", artifact.display()))?;
        if component_bytes(&bytes) {
            sha256_hex(&bytes)
        } else {
            "invalid-component-bytes".to_string()
        }
    } else {
        "gap".to_string()
    };

    Ok(Observed {
        component_sha256: component_digest(&log),
        core_module_cid: lab_cid(&log),
        bridge_entry: bridge_entry(&bridge_source),
        agent_host_component,
        agent_host_world: declared_world(&agent_source).unwrap_or_else(|| "absent".to_string()),
        agent_host_entrypoint: entrypoint,
        agent_host_build: marker(&build, "scripts/build-component-capsule.sh"),
        agent_host_lifecycle_entry: marker(&agent_source, LIFECYCLE_MARKER),
        agent_host_run: marker(&agent_source, RUN_MARKER),
        agent_host_export: marker(&agent_source, EXPORT_MARKER),
        falsify_command: falsify_command(&falsify_source),
    })
}

fn check_field(problems: &mut Vec<String>, record: &str, name: &str, tree: &str) {
    let found = record_field(record, name).unwrap_or("<missing>");
    if found != tree {
        problems.push(format!(
            "field {name}: record says {found:?}, tree says {tree:?}"
        ));
    }
}

/// When the LOG publishes a digest, the record must name the artifact path
/// and that file's bytes must hash to the same digest.
fn check_component_artifact(
    repo: &Path,
    record: &str,
    tree: &Observed,
    problems: &mut Vec<String>,
) {
    let found = record_field(record, "component_artifact").unwrap_or("<missing>");
    let digest = tree.component_sha256.as_str();
    if digest == "unpublished" {
        if found != "none" {
            problems.push(format!(
                "field component_artifact: record says {found:?}, tree says \"none\" \
                 because no LOG line names a component SHA-256"
            ));
        }
        return;
    }
    if digest == "ambiguous" {
        return;
    }
    if found == "none" || found == "<missing>" {
        problems.push(format!(
            "field component_artifact: record says {found:?}, tree says a path whose \
             bytes hash to {digest}"
        ));
        return;
    }
    match fs::read(repo.join(found)) {
        Ok(bytes) => {
            let actual = sha256_hex(&bytes);
            if actual != digest {
                problems.push(format!(
                    "field component_artifact: record says {found:?} with SHA-256 \
                     {actual}, tree says {digest} for the last matching LOG line"
                ));
            }
        }
        Err(err) => problems.push(format!(
            "field component_artifact: record says {found:?}, tree says it is \
             unreadable: {err}"
        )),
    }
}

fn mismatches(repo: &Path, record: &str, tree: &Observed) -> Vec<String> {
    let mut problems = Vec::new();
    check_field(
        &mut problems,
        record,
        "component_sha256",
        &tree.component_sha256,
    );
    check_field(
        &mut problems,
        record,
        "core_module_lab_cid",
        &tree.core_module_cid,
    );
    check_field(&mut problems, record, "bridge_entry", &tree.bridge_entry);
    check_field(
        &mut problems,
        record,
        "agent_host_component",
        &tree.agent_host_component,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_world",
        &tree.agent_host_world,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_entrypoint",
        &tree.agent_host_entrypoint,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_build",
        &tree.agent_host_build,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_lifecycle_entry",
        &tree.agent_host_lifecycle_entry,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_run",
        &tree.agent_host_run,
    );
    check_field(
        &mut problems,
        record,
        "agent_host_export",
        &tree.agent_host_export,
    );
    check_field(
        &mut problems,
        record,
        "falsify_command",
        &tree.falsify_command,
    );
    check_component_artifact(repo, record, tree, &mut problems);
    let prose = record.split_whitespace().collect::<Vec<_>>().join(" ");
    for claim in REQUIRED_PROSE {
        if !prose.contains(claim) {
            problems.push(format!(
                "prose {claim:?}: record says <missing>, tree says the claim is present"
            ));
        }
    }
    problems
}

fn read_record(repo: &Path) -> String {
    read(repo, RECORD_PATH).expect("DISCOVERY.md")
}

fn with_field(record: &str, key: &str, value: &str) -> String {
    let mut out = String::new();
    let mut replaced = false;
    for line in record.lines() {
        let matches = line
            .split_once(':')
            .is_some_and(|(found, _)| found.trim() == key);
        if matches && !replaced {
            out.push_str(key);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(replaced, "DISCOVERY.md has no {key} field");
    out
}

#[test]
fn discovery_matches_the_tree() {
    let repo = repo_root();
    let record = read_record(&repo);
    let tree = observe(&repo).expect("observe the tree");
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems.is_empty(),
        "{}\n{RECORD_STALE}",
        problems.join("\n")
    );
}

#[test]
fn component_digest_follows_the_append_only_log() {
    let older = format!("component {}", "a".repeat(64));
    let newer = format!("component {}", "b".repeat(64));
    assert_eq!(
        component_digest(&format!("{older}\n{newer}\n")),
        "b".repeat(64)
    );
    assert_eq!(component_digest(&older), "a".repeat(64));
    assert_eq!(
        component_digest("a component without a digest"),
        "unpublished"
    );

    let two_digests = format!("component {} {}", "a".repeat(64), "b".repeat(64));
    assert_eq!(component_digest(&two_digests), "ambiguous");
}

#[test]
fn bridge_entry_follows_the_hostcall_shape() {
    let unrelated = "impl StandIn {\n    pub fn unrelated(&self, id: &str) -> Result<String, String> {\n        Ok(String::new())\n    }\n}\n";
    assert_eq!(bridge_entry(unrelated), "none");

    let hostcall = "impl StandIn {\n    pub fn bridge(&self, line: &str, capsule_id: &str, principal: Option<&str>) -> Result<String, String> {\n        Ok(String::new())\n    }\n}\n";
    assert_eq!(bridge_entry(hostcall), "bridge");

    let async_but_shaped = "impl StandIn {\n    pub async fn bridge(&self, line: &str, capsule_id: &str, principal: Option<&str>) -> Result<String, String> {\n        Ok(String::new())\n    }\n}\n";
    assert_eq!(bridge_entry(async_but_shaped), "none");

    let wrong_error = "impl StandIn {\n    pub fn bridge(&self, line: &str, capsule_id: &str, principal: Option<&str>) -> Result<String, (u16, String)> {\n        Ok(String::new())\n    }\n}\n";
    assert_eq!(bridge_entry(wrong_error), "none");
}

#[test]
fn sha256_matches_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn planted_bridge_entry_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(
        &read_record(&repo),
        "bridge_entry",
        "planted-not-a-function",
    );
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field bridge_entry")),
        "{problems:?}"
    );
}

#[test]
fn planted_component_hash_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(&read_record(&repo), "component_sha256", &"0".repeat(64));
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field component_sha256")),
        "{problems:?}"
    );
}

#[test]
fn planted_component_artifact_path_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(
        &read_record(&repo),
        "component_artifact",
        "lab/two-capsule-run/README.md",
    );
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field component_artifact")),
        "{problems:?}"
    );
}

/// A published digest needs an artifact whose bytes hash to that digest. This
/// synthetic observation exercises that rule without touching the tree's LOG.
#[test]
fn planted_component_artifact_bytes_are_caught() {
    let repo = repo_root();
    let bytes = fs::read(repo.join("lab/two-capsule-run/README.md")).expect("README.md");
    let digest = sha256_hex(&bytes);

    let mut tree = observe(&repo).expect("observe the tree");
    tree.component_sha256 = digest.clone();

    let record = with_field(&read_record(&repo), "component_sha256", &digest);
    let record = with_field(
        &record,
        "component_artifact",
        "lab/two-capsule-run/README.md",
    );
    let accepted = mismatches(&repo, &record, &tree);
    assert!(
        !accepted
            .iter()
            .any(|problem| problem.contains("field component_artifact")),
        "{accepted:?}"
    );

    let wrong_file = with_field(
        &record,
        "component_artifact",
        "lab/two-capsule-run/Cargo.toml",
    );
    let caught = mismatches(&repo, &wrong_file, &tree);
    assert!(
        caught
            .iter()
            .any(|problem| problem.contains("field component_artifact")),
        "{caught:?}"
    );
}

#[test]
fn planted_agent_host_component_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(
        &read_record(&repo),
        "agent_host_component",
        "planted-not-a-component",
    );
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field agent_host_component")),
        "{problems:?}"
    );
}

#[test]
fn planted_agent_host_fields_are_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = read_record(&repo);
    let mutations = [
        ("agent_host_world", "planted-world"),
        ("agent_host_entrypoint", "planted.component.wasm"),
        ("agent_host_build", "planted-build.sh"),
        (
            "agent_host_lifecycle_entry",
            "impl exports::elastos::bus::lifecycle::Guest for Planted",
        ),
        ("agent_host_run", "fn run() -> Result<(), planted::Error>"),
        ("agent_host_export", "export!(Planted)"),
    ];
    for (field, value) in mutations {
        let planted = with_field(&record, field, value);
        let problems = mismatches(&repo, &planted, &tree);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains(&format!("field {field}"))),
            "mutation {field}: {problems:?}"
        );
    }
}

#[test]
fn planted_core_module_cid_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(
        &read_record(&repo),
        "core_module_lab_cid",
        &format!("lab-cid:sha256:{}", "0".repeat(64)),
    );
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field core_module_lab_cid")),
        "{problems:?}"
    );
}

#[test]
fn planted_falsify_command_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = with_field(&read_record(&repo), "falsify_command", "planted-command");
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("field falsify_command")),
        "{problems:?}"
    );
}

#[test]
fn planted_required_claim_is_caught() {
    let repo = repo_root();
    let tree = observe(&repo).expect("observe the tree");
    let record = read_record(&repo).replace("lab stand-in, not admission", "lab stand-in");
    let problems = mismatches(&repo, &record, &tree);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("prose")
                && problem.contains("lab stand-in, not admission")),
        "{problems:?}"
    );
}
