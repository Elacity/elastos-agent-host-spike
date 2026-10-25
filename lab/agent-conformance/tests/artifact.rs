use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use wasmparser::{Encoding, Parser, Payload, Validator};

fn lane() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_probe(round: usize) -> Vec<u8> {
    let lane = lane();
    let root = lane.parent().unwrap().parent().unwrap();
    let target = lane.join(format!("target/probe-build-{round}"));
    // Each round starts from an empty build directory: two cached reads are
    // insufficient evidence of reproducibility. All generated files are local.
    if target.exists() {
        fs::remove_dir_all(&target).unwrap();
    }
    fs::create_dir_all(target.join("tmp")).unwrap();
    let output = Command::new("bash")
        .arg(root.join("scripts/build-component-capsule.sh"))
        .arg(lane.join("probe"))
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", &target)
        .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
        .env("TMPDIR", target.join("tmp"))
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTFLAGS", "-Dwarnings")
        .output()
        .expect("start the existing component build script");
    assert!(
        output.status.success(),
        "component build {round} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let artifact = fs::read(lane.join("probe/agent-conformance-probe.component.wasm"))
        .expect("the build script must produce the component");
    fs::remove_dir_all(target).unwrap();
    artifact
}

fn builds() -> &'static [Vec<u8>; 2] {
    static BUILDS: OnceLock<[Vec<u8>; 2]> = OnceLock::new();
    BUILDS.get_or_init(|| [build_probe(1), build_probe(2)])
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
    // Keep the task's narrower three-interface boundary. The current Runtime
    // also supports capabilities/providers, but this blocked probe needs none.
    match name {
        "elastos:bus/types@1.0.0" | "elastos:bus/runtime@1.0.0" | "elastos:bus/identity@1.0.0" => {
            Ok(())
        }
        _ => Err("probe import is outside the supported ElastOS Bus interfaces"),
    }
}

#[test]
fn probe_imports_only_the_bus() {
    for artifact in builds() {
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
        "wasi:cli/environment@0.2.0",
        "host:files/read@1.0.0",
        "elastos:bus/capabilities@1.0.0",
        "elastos:bus/providers@1.0.0",
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
    let [first, second] = builds();
    let first_hash = format!("{:x}", Sha256::digest(first));
    let second_hash = format!("{:x}", Sha256::digest(second));
    assert_eq!(first_hash, second_hash, "independent builds differ");
    println!("probe component sha256:{first_hash}");
}

#[test]
fn probe_manifest_names_the_current_bus_world() {
    let lane = lane();
    let root = lane.parent().unwrap().parent().unwrap();
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
