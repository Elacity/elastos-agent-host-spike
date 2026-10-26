#[path = "common/probe.rs"]
mod probe;

use agent_conformance::build::{lane, offline_build, repository};
use probe::{build_probe, Effect};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use wasmparser::{Encoding, Parser, Payload, Validator};

fn builds() -> &'static [(Effect, [Vec<u8>; 2]); 3] {
    static BUILDS: OnceLock<[(Effect, [Vec<u8>; 2]); 3]> = OnceLock::new();
    BUILDS.get_or_init(|| {
        [Effect::Default, Effect::Read, Effect::Network]
            .map(|effect| (effect, [build_probe(effect, 1), build_probe(effect, 2)]))
    })
}

fn imports(bytes: &[u8]) -> Result<Vec<String>, &'static str> {
    if !Parser::is_component(bytes) {
        return Err("probe artifact is not a component");
    }
    Validator::new()
        .validate_all(bytes)
        .map_err(|_| "probe component is invalid")?;
    let mut depth = 0;
    let mut names = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("validated component must parse") {
            Payload::Version {
                encoding: Encoding::Component | Encoding::Module,
                ..
            } => depth += 1,
            Payload::End(_) => depth -= 1,
            Payload::ComponentImportSection(section) if depth == 1 => {
                for import in section {
                    names.push(
                        import
                            .expect("validated component import must parse")
                            .name
                            .0
                            .to_owned(),
                    );
                }
            }
            _ => {}
        }
    }
    Ok(names)
}

fn allowed_import(name: &str) -> Result<(), &'static str> {
    // Match the Bus v1 admission subset used by the effect builds.
    match name {
        "elastos:bus/types@1.0.0"
        | "elastos:bus/runtime@1.0.0"
        | "elastos:bus/identity@1.0.0"
        | "elastos:bus/capabilities@1.0.0"
        | "elastos:bus/providers@1.0.0" => Ok(()),
        _ => Err("probe import is outside the supported ElastOS Bus interfaces"),
    }
}

#[test]
fn probe_imports_only_the_bus() {
    for artifact in builds().iter().flat_map(|(_, pair)| pair) {
        let names = imports(artifact).unwrap();
        assert!(!names.is_empty(), "the component must import the Bus types");
        for name in names {
            assert_eq!(allowed_import(&name), Ok(()), "unexpected import {name}");
        }
    }
}

#[test]
fn foreign_and_wrong_version_imports_are_refused() {
    for name in [
        "elastos:bus/capabilities@1.0.0",
        "elastos:bus/providers@1.0.0",
    ] {
        assert_eq!(allowed_import(name), Ok(()));
    }
    for name in [
        "wasi:cli/environment@0.2.0",
        "host:files/read@1.0.0",
        "elastos:bus/capabilities@2.0.0",
        "elastos:bus/providers@2.0.0",
        "elastos:bus/unknown@1.0.0",
        "elastos:bus/providers@1.0.0/extra",
    ] {
        assert_eq!(
            allowed_import(name),
            Err("probe import is outside the supported ElastOS Bus interfaces")
        );
    }
}

#[test]
fn non_component_and_invalid_component_are_refused() {
    assert_eq!(
        imports(b"not wasm"),
        Err("probe artifact is not a component")
    );
    assert_eq!(
        imports(b"\0asm\x01\0\0\0"),
        Err("probe artifact is not a component")
    );
    assert_eq!(
        imports(b"\0asm\x0d\0\x01\0\xff"),
        Err("probe component is invalid")
    );
}

#[test]
fn probe_hash_is_stable() {
    // Same-machine artifact evidence only. Cargo symbol hashes vary by host;
    // this SHA-256 is neither a published bundle CID nor Runtime admission.
    let mut hashes = std::collections::BTreeSet::new();
    for (effect, [first, second]) in builds() {
        let first_hash = format!("{:x}", Sha256::digest(first));
        let second_hash = format!("{:x}", Sha256::digest(second));
        assert_eq!(
            first_hash, second_hash,
            "independent {effect:?} builds differ"
        );
        assert!(
            hashes.insert(first_hash.clone()),
            "effects must have distinct bytes"
        );
        println!(
            "probe component sha256:{first_hash} effect:{}",
            effect.name()
        );
    }
}

#[test]
fn probe_manifest_names_the_current_bus_world() {
    let lane = lane();
    let root = repository();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(lane.join("probe/capsule.json")).unwrap()).unwrap();
    let wit = fs::read(root.join("elastos/wit/elastos-bus-v1.wit")).unwrap();
    assert_eq!(
        manifest["wit_world_sha256"],
        format!("{:x}", Sha256::digest(wit))
    );
    assert_eq!(manifest["runtime_abi"], "elastos.component/v1");
    assert_eq!(manifest["bus_contract"], "elastos:bus@v1");
    assert_eq!(manifest["execution"], "component");
    let entrypoint = manifest["entrypoint"].as_str().unwrap();
    assert_eq!(Path::new(entrypoint).components().count(), 1);
    assert_eq!(entrypoint, "agent-conformance-probe.component.wasm");
    assert_eq!(manifest["capabilities"], serde_json::json!([]));
}

#[test]
fn probe_effects_are_exclusive() {
    let _ = builds();
    let output = offline_build("cargo", &lane().join("target/probe-feature-check"))
        .unwrap()
        .args([
            "check",
            "--locked",
            "--offline",
            "--manifest-path",
            "lab/agent-conformance/probe/Cargo.toml",
            "--features",
            "read,network",
        ])
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .unwrap();
    assert!(!output.status.success(), "two effects must be refused");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("select exactly one probe effect: read or network"));
}
