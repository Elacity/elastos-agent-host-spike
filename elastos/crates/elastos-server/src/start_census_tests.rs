//! Census of capsule starts.
//!
//! One test finds every production call of a capsule load, a capsule spawn or
//! `register_capsule` in `elastos-server` and `elastos-runtime`, and fails
//! unless each call sits in a place this file lists with the gate named in one
//! short phrase.
//!
//! Test code is left out by construction. The sources are the closure of
//! `mod` and `include!` from each crate root (`lib.rs` and `main.rs`) after
//! every `#[cfg(test)]` item is removed. So an inline test module, a
//! `mod tests;` declaration and a file included only from a test module are
//! never read. This module is not reachable from those roots, and every needle
//! below is built from parts at run time, so this file never counts itself.
//!
//! A capsule load or spawn is one of:
//!
//! - `.load`, `.start`, `.start_resident`, `.load_admitted` or
//!   `.load_admitted_sealed` on a
//!   compute-provider receiver: `component`, `compute`, `vm`, `crosvm`, `vz`,
//!   or any name that ends in `provider`;
//! - `.launch_capsule`, the supervisor's VM launch;
//! - native provider bridge spawns and every zero-argument call to `spawn`,
//!   including command builders for host process starts;
//! - `.register_capsule`.
//!
//! VM launches and native provider spawns use the `P2-2` gate phrase. Other
//! zero-argument spawns name their actual role. The list is the tree as it is
//! today; slice 5 tightens the folder gate after this one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// A listed caller: the file, the function that makes the call, the call as a
/// label, how many times that function makes it, and the gate in one phrase.
struct Place {
    file: String,
    function: String,
    label: String,
    calls: usize,
    gate: String,
}

/// One call found in the sources.
pub(super) struct Site {
    pub(super) file: String,
    pub(super) function: String,
    pub(super) label: String,
}

/// The needle fragments. They are joined only at run time.
const LOAD: &[&str] = &["lo", "ad"];
const START: &[&str] = &["sta", "rt"];
const START_RESIDENT: &[&str] = &["start_", "resident"];
const LOAD_ADMITTED: &[&str] = &["load_", "admitted"];
const LOAD_SEALED: &[&str] = &["load_admitted_", "sealed"];
const REGISTER: &[&str] = &["register_", "capsule"];
const LAUNCH: &[&str] = &["launch_", "capsule"];
const SPAWN: &[&str] = &["Provider", "Bridge::spawn"];
const COMMAND_SPAWN: &[&str] = &[".", "spa", "wn()"];
const CONFINED_EXEC: &[&str] = &["libc::f", "execve("];
const PATH_EXEC: &[&str] = &["libc::", "execve("];

/// The gate of the paths that B1-R does not cover yet.
const P2_2: &str = "P2-2 (not gated by B1-R yet)";

fn joined(parts: &[&str]) -> String {
    parts.concat()
}

fn label_of(receiver: &str, method: &str) -> String {
    [receiver, ".", method].concat()
}

fn place(file: &str, function: &str, label: String, calls: usize, gate: &str) -> Place {
    Place {
        file: file.to_string(),
        function: function.to_string(),
        label,
        calls,
        gate: gate.to_string(),
    }
}

/// Every production caller of a capsule load, spawn or registration, with the
/// gate that holds it. A row is stale the moment its call moves or the
/// function it names goes away.
fn places() -> Vec<Place> {
    let load = joined(LOAD);
    let start = joined(START);
    let resident = joined(START_RESIDENT);
    let admitted = joined(LOAD_ADMITTED);
    let sealed = joined(LOAD_SEALED);
    let register = joined(REGISTER);
    let launch = joined(LAUNCH);
    let spawn = joined(SPAWN);
    vec![
        place(
            "elastos-server/src/runtime.rs",
            "load_dev_unsigned_component",
            label_of("component", &admitted),
            1,
            "dev mode only: owner set dev_mode = true; nothing checked",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "run_signer",
            label_of("component", &admitted),
            1,
            "folder start: admitted walk CID, signer; requires refused",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "run_signer",
            label_of("provider", &load),
            1,
            "folder start: trusted key, dev mode, or installed release",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "start_by_bundle",
            label_of("component", &admitted),
            1,
            "start by CID: verified bundle CID; signature checked separately",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "start_by_bundle",
            label_of("component", &sealed),
            1,
            "start by CID: verified bundle CID; signature checked separately",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "start_loaded",
            label_of("provider", &start),
            1,
            "runs the capsule its start loaded",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "start_loaded",
            register.clone(),
            1,
            "records the capsule its start loaded",
        ),
        place(
            "elastos-server/src/runtime.rs",
            "watch_activation",
            label_of("component", &resident),
            1,
            "resident start: admitted component handle and held activation",
        ),
        place(
            "elastos-server/src/carrier_service.rs",
            "spawn",
            "spawn()".to_string(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/carrier_service.rs",
            "send_raw_blocking",
            "spawn()".to_string(),
            1,
            P2_2,
        ),
        place(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_command",
            "spawn()".to_string(),
            1,
            P2_2,
        ),
        place(
            "elastos-runtime/src/provider/os_entry.rs",
            "macos_start",
            "spawn()".to_string(),
            1,
            "admitted grant, checked storage, Seatbelt profile",
        ),
        place(
            "elastos-runtime/src/provider/failure_record.rs",
            "launch",
            "libc::fexecve".to_string(),
            1,
            "B3 S10: admitted rights, checked root identity, bound executable",
        ),
        place(
            "elastos-server/src/setup/verified_executable.rs",
            "attach_std",
            "libc::fexecve".to_string(),
            1,
            "P2-8 slice 2: held descriptor matched the signed release digest at start",
        ),
        place(
            "elastos-server/src/carrier.rs",
            "start_carrier_node_with_network",
            "spawn()".to_string(),
            1,
            "Carrier network router; outside capsule start",
        ),
        place(
            "elastos-server/src/main.rs",
            "serve_web_capsule",
            "spawn()".to_string(),
            1,
            "shell capsule: verified installed binary; P2-2",
        ),
        place(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            "spawn()".to_string(),
            1,
            "shell capsule: verified installed binary; P2-2",
        ),
        place(
            "elastos-server/src/setup/browser_linux.rs",
            "run_host_command",
            "spawn()".to_string(),
            1,
            "Browser setup helper; outside capsule start",
        ),
        place(
            "elastos-server/src/update_controller/child.rs",
            "spawn",
            "spawn()".to_string(),
            1,
            "owned update child process; outside capsule start",
        ),
        place(
            "elastos-server/src/api/gateway_home_terminal.rs",
            "start_home_terminal_session",
            "spawn()".to_string(),
            1,
            "terminal start: policy and host binding checked at process gate",
        ),
        place(
            "elastos-server/src/main.rs",
            "open_browser",
            "spawn()".to_string(),
            2,
            "OS URL opener; no capsule starts",
        ),
        place(
            "elastos-server/src/protected_content_config.rs",
            "provision_custody_node_with_installed_provider",
            "spawn()".to_string(),
            1,
            "provisioning: verified custody provider binary",
        ),
        place(
            "elastos-server/src/publish.rs",
            "start",
            "spawn()".to_string(),
            1,
            "publication model import provider; outside capsule start",
        ),
        place(
            "elastos-server/src/runtime_control.rs",
            "ensure_managed_runtime",
            "spawn()".to_string(),
            1,
            "signed release binary held at start; source Home dev_mode = true",
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "spawn_browser_local_exit",
            "spawn()".to_string(),
            1,
            "Browser local Exit helper; outside capsule start",
        ),
        place(
            "elastos-server/src/setup.rs",
            "probe_arm64_model_engine",
            "spawn()".to_string(),
            1,
            "setup compatibility probe; outside capsule start",
        ),
        place(
            "elastos-server/src/setup/browser_config.rs",
            "generate_with_migration",
            "spawn()".to_string(),
            1,
            "Browser config generator; outside capsule start",
        ),
        place(
            "elastos-server/src/setup/browser_config.rs",
            "probe_native_host",
            "spawn()".to_string(),
            1,
            "Browser host capability probe; outside capsule start",
        ),
        place(
            "elastos-server/src/update.rs",
            "verify_installed_binary_version",
            "spawn()".to_string(),
            1,
            "update version probe; outside capsule start",
        ),
        place(
            "elastos-runtime/src/capsule/manager.rs",
            "launch_internal",
            label_of("compute", &load),
            1,
            "caller's trust level (shell bootstrap or LaunchCapsule request)",
        ),
        place(
            "elastos-runtime/src/capsule/manager.rs",
            "launch_internal",
            label_of("compute", &start),
            1,
            "caller's trust level (shell bootstrap or LaunchCapsule request)",
        ),
        // The load moved into load_microvm_capsule, which checks the entrypoint first.
        place(
            "elastos-server/src/serve_cmd.rs",
            "load_microvm_capsule",
            label_of("provider", &load),
            1,
            "entrypoint file checked before MicroVM load; P2-2 authority pending",
        ),
        place(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            label_of("vm_provider", &start),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            register.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/supervisor.rs",
            "handle_request",
            launch.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/supervisor.rs",
            "launch_capsule",
            label_of("vm", &start),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            spawn.clone(),
            14,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "apply",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "start_did_provider",
            [spawn.as_str(), "_confined"].concat(),
            1,
            "DID: admitted binary and confined storage",
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "register_ipfs_provider_plane_with_role",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "register_availability_provider_plane",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "register_chain_provider_plane",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/server_infra.rs",
            "start_wallet_provider",
            [spawn.as_str(), "_confined"].concat(),
            1,
            "Wallet: admitted binary, OS gate, confined storage",
        ),
        place(
            "elastos-server/src/protected_content_runtime.rs",
            "register_inactive_custody_provider",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/protected_content_runtime.rs",
            "register_protect_provider",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/protected_content_runtime.rs",
            "register_protected_content_decrypt_provider",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/main.rs",
            "get_operator_ipfs_bridge",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/main.rs",
            "get_content_registry_with_local_ipfs_backend",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/main.rs",
            "get_tunnel_bridge",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/gateway_cmd.rs",
            "register_installed_ipfs_provider",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/site_cmd.rs",
            "get_site_bridge",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/site_cmd.rs",
            "get_tunnel_bridge",
            spawn.clone(),
            1,
            P2_2,
        ),
        place(
            "elastos-server/src/webspace_cmd.rs",
            "spawn_webspace_bridge",
            spawn.clone(),
            1,
            P2_2,
        ),
    ]
}

/// One row: every found call is listed, and every listed place still has its
/// calls. A new caller, a removed row and a renamed function each fail it.
#[test]
fn every_capsule_load_spawn_and_registration_is_listed_with_its_gate() {
    let sources = production_sources();
    assert!(
        !sources
            .keys()
            .any(|file| file.ends_with("start_census_tests.rs")),
        "this file must not be in the production set"
    );

    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (file, text) in &sources {
        for site in sites(file, text) {
            *found
                .entry((site.file, site.label, site.function))
                .or_default() += 1;
        }
    }

    let listed = places();
    let mut keys = BTreeSet::new();
    for place in &listed {
        assert!(!place.gate.trim().is_empty(), "{}: no gate", place.file);
        assert!(
            place.gate.len() <= 72,
            "{}: the gate is one short phrase",
            place.file
        );
        let key = (
            place.file.clone(),
            place.label.clone(),
            place.function.clone(),
        );
        assert!(keys.insert(key.clone()), "{key:?} is listed twice");
        let calls = found.get(&key).copied().unwrap_or(0);
        assert_eq!(
            calls, place.calls,
            "stale or moved row for {key:?}: {} of {} calls found",
            calls, place.calls
        );
    }

    let mut unlisted: Vec<(&(String, String, String), &usize)> = found
        .iter()
        .filter(|(key, _)| !keys.contains(*key))
        .collect();
    unlisted.sort();
    assert!(unlisted.is_empty(), "unlisted callers: {unlisted:#?}");
}

/// Each row proves that a named check in the load's own function precedes the
/// listed load. Keep this separate from the authority label: a regular file
/// check does not establish the capsule's signing authority.
#[test]
fn census_preload_checks_run_before_their_loads() {
    let sources = production_sources();
    let required_orders = [(
        "elastos-server/src/serve_cmd.rs",
        "load_microvm_capsule",
        "check_entrypoint_file(",
        "provider.load",
    )];

    for (file, function, check, load) in required_orders {
        let code = code_only(sources.get(file).expect("listed load source exists"));
        let check_sites: Vec<_> = code
            .match_indices(check)
            .map(|(at, _)| at)
            .filter(|&at| enclosing_fn(&code, at) == function)
            .collect();
        let load_sites: Vec<_> = code
            .match_indices(".load(")
            .map(|(at, _)| at)
            .filter(|&at| {
                enclosing_fn(&code, at) == function
                    && label_of(receiver_before(&code, at), "load") == load
            })
            .collect();
        assert_eq!(
            check_sites.len(),
            1,
            "{file}:{function}: expected one {check}"
        );
        assert_eq!(
            load_sites.len(),
            1,
            "{file}:{function}: expected one {load}"
        );
        assert!(
            check_sites[0] < load_sites[0],
            "{file}:{function}: {check} must precede {load}"
        );
    }
}

/// Every `.load`, `.start`, `.load_admitted`, `.load_admitted_sealed`,
/// `.launch_capsule` and `.register_capsule` call, and every `ProviderBridge`
/// spawn, in one file's production text.
pub(super) fn sites(file: &str, text: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    let code = code_only(text);
    for parts in [LOAD_SEALED, LOAD_ADMITTED, START_RESIDENT, LOAD, START] {
        let method = joined(parts);
        let needle = [".", method.as_str(), "("].concat();
        for (at, _) in code.match_indices(&needle) {
            let receiver = receiver_before(&code, at);
            if !is_capsule_host(receiver) {
                continue;
            }
            sites.push(Site {
                file: file.to_string(),
                function: enclosing_fn(&code, at),
                label: label_of(receiver, &method),
            });
        }
    }
    for parts in [REGISTER, LAUNCH] {
        let method = joined(parts);
        let needle = [".", method.as_str(), "("].concat();
        for (at, _) in code.match_indices(&needle) {
            sites.push(Site {
                file: file.to_string(),
                function: enclosing_fn(&code, at),
                label: method.clone(),
            });
        }
    }
    let spawn = joined(SPAWN);
    let confined_spawn = [spawn.as_str(), "_confined"].concat();
    for (at, _) in code.match_indices(&spawn) {
        let suffix = &code[at + spawn.len()..];
        let label = if suffix
            .strip_prefix("_confined")
            .is_some_and(|tail| tail.trim_start().starts_with('('))
        {
            confined_spawn.clone()
        } else {
            spawn.clone()
        };
        sites.push(Site {
            file: file.to_string(),
            function: enclosing_fn(&code, at),
            label,
        });
    }
    for at in zero_argument_spawns(&code) {
        sites.push(Site {
            file: file.to_string(),
            function: enclosing_fn(&code, at),
            label: "spawn()".to_string(),
        });
    }
    for (needle, label) in [
        (CONFINED_EXEC, "libc::fexecve"),
        (PATH_EXEC, "libc::execve"),
    ] {
        for (at, _) in code.match_indices(&joined(needle)) {
            sites.push(Site {
                file: file.to_string(),
                function: enclosing_fn(&code, at),
                label: label.to_string(),
            });
        }
    }
    sites
}

/// Keep byte positions, but remove strings and comments before looking for
/// calls or item boundaries. A quoted example cannot become a caller.
pub(super) fn code_only(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut code = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i..].starts_with(b"//") {
            i = line_end(bytes, i);
        } else if bytes[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while i + 1 < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            let raw = if bytes[i] == b'r' {
                Some(i)
            } else if bytes[i..].starts_with(b"br") {
                Some(i + 1)
            } else {
                None
            };
            let mut hashes = 0;
            if let Some(r) = raw {
                while bytes.get(r + 1 + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if bytes.get(r + 1 + hashes) == Some(&b'"') {
                    i = r + 2 + hashes;
                    while i < bytes.len() {
                        if bytes[i] == b'"'
                            && (0..hashes).all(|n| bytes.get(i + 1 + n) == Some(&b'#'))
                        {
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                }
            }
            if i == start && (bytes[i] == b'"' || bytes[i..].starts_with(b"b\"")) {
                i += if bytes[i] == b'b' { 2 } else { 1 };
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else if bytes[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            if i == start && bytes[i] == b'\'' {
                let close = if bytes.get(i + 1) == Some(&b'\\') {
                    i + 3
                } else {
                    i + 2
                };
                if bytes.get(close) == Some(&b'\'') {
                    i = close + 1;
                }
            }
        }
        if i == start {
            i += 1;
        } else {
            for byte in &mut code[start..i.min(bytes.len())] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
        }
    }
    String::from_utf8(code).expect("mask keeps UTF-8 positions")
}

/// A zero-argument spawn can start a host process even if its command builder
/// has an unfamiliar local name. List every such production call.
fn zero_argument_spawns(code: &str) -> Vec<usize> {
    code.match_indices(&joined(COMMAND_SPAWN))
        .map(|(at, _)| at)
        .collect()
}

/// The receivers that hold a compute provider. A new provider field named
/// `...provider` is covered without an edit here.
fn is_capsule_host(receiver: &str) -> bool {
    receiver.ends_with("provider")
        || matches!(receiver, "component" | "compute" | "vm" | "crosvm" | "vz")
}

/// The identifier before the `.` of a method call, skipping the whitespace a
/// wrapped call puts between the two.
pub(crate) fn receiver_before(text: &str, dot: usize) -> &str {
    let bytes = text.as_bytes();
    let mut end = dot;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    &text[start..end]
}

/// The name of the nearest function above `at`.
pub(super) fn enclosing_fn(text: &str, at: usize) -> String {
    let mut end = at;
    loop {
        let start = text[..end].rfind('\n').map(|index| index + 1).unwrap_or(0);
        let line = &text[start..end];
        if !line.trim_start().starts_with("//") {
            if let Some(name) = fn_name(line) {
                return name.to_string();
            }
        }
        if start == 0 {
            return String::new();
        }
        end = start - 1;
    }
}

/// The name on a line that declares a function, when the line declares one.
fn fn_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let at = trimmed.find("fn ")?;
    if !fn_prefix(&trimmed[..at]) {
        return None;
    }
    let after = &trimmed[at + 3..];
    let name_end = after.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    if name_end == 0 {
        return None;
    }
    let rest = after[name_end..].trim_start();
    if rest.starts_with('(') || rest.starts_with('<') {
        Some(&after[..name_end])
    } else {
        None
    }
}

/// The qualifiers a function declaration may carry before its `fn`.
fn fn_prefix(prefix: &str) -> bool {
    let mut words = prefix.split_whitespace();
    words.all(|word| {
        word.starts_with("pub")
            || word.starts_with('"')
            || word.ends_with(')') && word.starts_with("crate")
            || matches!(word, "async" | "unsafe" | "const" | "extern" | "default")
    })
}

/// A map of every file each crate compiles for production, keyed from the
/// crates directory, with every `#[cfg(test)]` item removed.
pub(super) fn production_sources() -> BTreeMap<String, String> {
    let crates = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crates directory"),
    )
    .expect("the crates directory exists");
    let mut queue = vec![
        crates.join("elastos-server/src/lib.rs"),
        crates.join("elastos-server/src/main.rs"),
        crates.join("elastos-runtime/src/lib.rs"),
    ];
    let mut sources = BTreeMap::new();
    while let Some(path) = queue.pop() {
        let path = fs::canonicalize(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
        let file = path
            .strip_prefix(&crates)
            .expect("under the crates directory")
            .to_string_lossy()
            .replace('\\', "/");
        if sources.contains_key(&file) {
            continue;
        }
        // A Windows checkout may use CRLF line endings; the census needles are LF.
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        let text = without_test_items(&raw);
        queue.extend(children(&path, &text));
        sources.insert(file, text);
    }
    sources
}

/// Every module file and included file one source names.
fn children(path: &Path, text: &str) -> Vec<PathBuf> {
    let dir = path.parent().expect("a parent directory");
    let mut found = Vec::new();
    let mut path_attr: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#[path") {
            path_attr = quoted(rest);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        if let Some(name) = module_decl(trimmed) {
            if let Some(resolved) = resolve_module(path, name, path_attr.take().as_deref()) {
                found.push(resolved);
            }
            continue;
        }
        path_attr = None;
    }
    for (at, _) in text.match_indices("include!(") {
        let rest = &text[at + "include!(".len()..];
        if let Some(relative) = quoted(rest) {
            if relative.ends_with(".rs") {
                let candidate = dir.join(relative);
                if candidate.is_file() {
                    found.push(candidate);
                }
            }
        }
    }
    found
}

/// The first string literal in `rest`.
fn quoted(rest: &str) -> Option<String> {
    let open = rest.find('"')?;
    let close = rest[open + 1..].find('"')?;
    Some(rest[open + 1..open + 1 + close].to_string())
}

/// The module name on a line that declares a module file.
fn module_decl(line: &str) -> Option<&str> {
    let mut rest = line;
    while let Some(after) = rest.strip_prefix("pub") {
        let after = after.trim_start();
        let after = match after.strip_prefix('(') {
            Some(inside) => inside[inside.find(')')? + 1..].trim_start(),
            None => after,
        };
        rest = after;
    }
    let rest = rest.strip_prefix("mod ")?;
    let name = rest.trim_start();
    let end = name.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    if end == 0 || name[end..].trim_start() != ";" {
        return None;
    }
    Some(&name[..end])
}

/// The file a `mod name;` or `#[path]` declaration names.
fn resolve_module(from: &Path, name: &str, path_attr: Option<&str>) -> Option<PathBuf> {
    let dir = from.parent()?;
    if let Some(attr) = path_attr {
        let candidate = dir.join(attr);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let base = from.file_name()?.to_string_lossy();
    let root = if base == "lib.rs" || base == "main.rs" || base == "mod.rs" {
        dir.to_path_buf()
    } else {
        dir.join(base.trim_end_matches(".rs"))
    };
    let flat = root.join(format!("{name}.rs"));
    if flat.is_file() {
        return Some(flat);
    }
    let nested = root.join(name).join("mod.rs");
    if nested.is_file() {
        return Some(nested);
    }
    None
}

/// `text` with every item that carries `#[cfg(test)]` or
/// `#[cfg(all(test, ...))]` removed.
pub(super) fn without_test_items(text: &str) -> String {
    let code = code_only(text);
    let bytes = code.as_bytes();
    let mut out = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some((start, end)) = next_test_attribute(&code, cursor) else {
            out.push_str(&text[cursor..]);
            break;
        };
        out.push_str(&text[cursor..start]);
        cursor = item_end(bytes, end);
    }
    out
}

/// The range of the next attribute that makes its item test-only.
fn next_test_attribute(text: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut at = from;
    while let Some(found) = text[at..].find("#[cfg(") {
        let start = at + found;
        let open = start + "#[cfg(".len();
        let mut depth = 0usize;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            i += 1;
        }
        if i < bytes.len() && bytes.get(i + 1) == Some(&b']') && test_only(&text[open..i]) {
            return Some((start, i + 2));
        }
        at = start + 1;
    }
    None
}

/// Whether a `cfg` predicate holds only in a test build.
fn test_only(expr: &str) -> bool {
    if expr == "test" {
        return true;
    }
    let Some(inner) = expr
        .strip_prefix("all(")
        .and_then(|it| it.strip_suffix(')'))
    else {
        return false;
    };
    let mut depth = 0i32;
    let mut begin = 0;
    let mut parts = Vec::new();
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(inner[begin..i].trim());
                begin = i + 1;
            }
            _ => {}
        }
    }
    parts.push(inner[begin..].trim());
    parts.contains(&"test")
}

/// The index after the item that starts at `from`. A test field ends at its
/// comma; a test module ends at its matching brace. The code mask makes
/// comments and literals inert for both boundaries.
fn item_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < bytes.len() && bytes[i] == b'#' && bytes[i + 1] == b'[' {
            i = skip_bracketed(bytes, i + 1);
            continue;
        }
        break;
    }
    let mut parens = 0i32;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b'(' | b'[' => parens += 1,
            b')' | b']' => parens -= 1,
            b'{' if parens <= 0 => return skip_braced(bytes, i),
            b';' | b',' if parens <= 0 => return i + 1,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

fn line_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| from + offset + 1)
        .unwrap_or(bytes.len())
}

/// The index after the `]` that closes the `[` at `open`.
fn skip_bracketed(bytes: &[u8], open: usize) -> usize {
    skip_pairs(bytes, open, b'[', b']')
}

/// The index after the `}` that closes the `{` at `open`.
fn skip_braced(bytes: &[u8], open: usize) -> usize {
    skip_pairs(bytes, open, b'{', b'}')
}

fn skip_pairs(bytes: &[u8], open: usize, left: u8, right: u8) -> usize {
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            byte if byte == left => depth += 1,
            byte if byte == right => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

#[test]
fn test_item_filter_uses_field_and_module_boundaries() {
    let source = r##"
struct Example {
    #[cfg(test)]
    test_count: usize,
    live_count: usize,
}
#[cfg(test)]
mod tests {
    // } must not close the module
    const EXAMPLE: &str = r#"{"#;
    fn hidden() { component.start_resident(&handle); }
}
fn production() { component.start_resident(&handle); }
"##;
    let filtered = without_test_items(source);
    assert!(filtered.contains("live_count: usize"));
    assert!(filtered.contains("fn production()"));
    assert!(!filtered.contains("test_count: usize"));
    assert!(!filtered.contains("fn hidden()"));
    assert_eq!(sites("sample.rs", &filtered).len(), 1);

    let sources = production_sources();
    let bridge = &sources["elastos-server/src/resource_bridge.rs"];
    assert!(bridge.contains("fn plain_output_name"));
    assert!(!bridge.contains("fn block_end"));
    assert!(!bridge.contains("test_count: usize"));
    let broker = &sources["elastos-runtime/src/provider/local_model_broker.rs"];
    assert!(!broker.contains("only_owned_engine_and_exact_route_are_forwarded"));
}

#[test]
fn census_source_cannot_supply_its_own_spawn_site() {
    let own = include_str!("start_census_tests.rs");
    assert!(sites("start_census_tests.rs", own).is_empty());
}
