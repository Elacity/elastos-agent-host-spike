//! wc-008: does `elastos.capsule/v1` have a runtime ABI for a bare capsule,
//! this lane's zero-import core Wasm module that is not a Component?
//!
//! The answer, from the Runtime's own code (ADOPTION.md, "Runtime ABI for a
//! bare capsule (wc-008)"), is no: `NO_ABI_FOR_BARE_CAPSULE`. This file
//! records that gap as SKIPPED, never PASS, shows each of the seven
//! `CapsuleRuntimeAbi` values refused for this capsule with the value's own
//! reason, and checks that a field the lab might invent is refused by name.
//! It picks no near-fit ABI and adds no field (PRINCIPLES P11, P13, P18).
//!
//! The tests live in the root package because the lane gate tests only that
//! package. They share one process, so none changes process-wide state.

mod common;

use capsule_identity::Refusal;
use common::build::TempDir;
use elastos_common::{CapsuleManifest, CapsuleRuntimeAbi};
use serde_json::{Map, Value};
use std::fs;
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// The finding's code, copied to this lane's INBOX for Flint.
const NO_ABI: &str = "NO_ABI_FOR_BARE_CAPSULE";

/// Every `CapsuleRuntimeAbi` value. [`abi_rule`]'s `match` has no wildcard
/// arm, so a new value in the Runtime fails this file's build and forces a
/// fresh look at the question.
const ALL_ABIS: [CapsuleRuntimeAbi; 7] = [
    CapsuleRuntimeAbi::NativeHost,
    CapsuleRuntimeAbi::ProviderStdioV1,
    CapsuleRuntimeAbi::WasiPreview1,
    CapsuleRuntimeAbi::RuntimeProjectionV1,
    CapsuleRuntimeAbi::ElastosComponentV1,
    CapsuleRuntimeAbi::MicrovmLinux,
    CapsuleRuntimeAbi::Data,
];

/// One ABI's rule in `elastos/crates/elastos-common/src/manifest.rs`: its
/// wire name, the metadata it needs (or that it is refused), and the exact
/// reason `validate()` gives when this capsule's manifest declares it.
struct AbiRule {
    wire: &'static str,
    needs: &'static str,
    reason: &'static str,
}

fn abi_rule(abi: &CapsuleRuntimeAbi) -> AbiRule {
    match abi {
        CapsuleRuntimeAbi::NativeHost => AbiRule {
            wire: "native-host",
            needs: "shell metadata (manifest.rs:866-881)",
            reason: "native-host metadata describes only the existing trusted shell helper: role=shell, name=shell, entrypoint=shell, type/execution/runtime_abi=native-host",
        },
        CapsuleRuntimeAbi::ProviderStdioV1 => AbiRule {
            wire: "elastos.provider-stdio/v1",
            needs: "native provider metadata (manifest.rs:848-865)",
            reason: "native providers require role=provider, type=native-provider, execution=native-provider and runtime_abi=elastos.provider-stdio/v1",
        },
        CapsuleRuntimeAbi::WasiPreview1 => AbiRule {
            wire: "wasi-preview1",
            needs: "nothing: refused outright (manifest.rs:738-743)",
            reason: "WASI Preview 1 is not a supported product capsule ABI; use elastos.component/v1 or elastos.runtime-projection/v1",
        },
        CapsuleRuntimeAbi::RuntimeProjectionV1 => AbiRule {
            wire: "elastos.runtime-projection/v1",
            needs: "web projection metadata (manifest.rs:802-846)",
            reason: "web projection capsules must declare execution=web-projection",
        },
        CapsuleRuntimeAbi::ElastosComponentV1 => AbiRule {
            wire: "elastos.component/v1",
            needs: "Component metadata (manifest.rs:775-801)",
            reason: "component capsules must declare execution=\"component\"",
        },
        CapsuleRuntimeAbi::MicrovmLinux => AbiRule {
            wire: "microvm-linux",
            needs: "microVM metadata, type=microvm (manifest.rs:882-888)",
            reason: "microVM execution metadata requires type=microvm",
        },
        CapsuleRuntimeAbi::Data => AbiRule {
            wire: "data",
            needs: "data metadata, type=data (manifest.rs:889-894)",
            reason: "data execution metadata requires type=data",
        },
    }
}

/// This capsule's manifest bytes with one more top-level `key`, in memory.
/// The committed `capsule/capsule.json` is never changed.
fn manifest_with(key: &str, value: Value) -> Vec<u8> {
    let mut fields: Map<String, Value> =
        serde_json::from_slice(CAPSULE_MANIFEST).expect("capsule.json is a JSON object");
    fields.insert(key.to_owned(), value);
    serde_json::to_vec_pretty(&fields).expect("serialize the manifest")
}

#[test]
#[ignore = "NO_ABI_FOR_BARE_CAPSULE: elastos.capsule/v1 has no runtime_abi for a bare core Wasm module (not a Component); gap for Anders, https://github.com/Elacity/elastos-runtime/issues/463"]
fn bare_capsule_runtime_abi_is_recorded_as_skipped() {
    panic!("NO_ABI_FOR_BARE_CAPSULE: elastos.capsule/v1 has no runtime_abi for a bare core Wasm module (not a Component); gap for Anders, https://github.com/Elacity/elastos-runtime/issues/463");
}

#[test]
fn no_runtime_abi_names_a_bare_core_module() {
    let mut results = Vec::new();
    let mut wrong = Vec::new();
    for abi in &ALL_ABIS {
        let rule = abi_rule(abi);
        let wire = serde_json::to_value(abi).expect("serialize the ABI");
        assert_eq!(wire, Value::from(rule.wire), "the ABI's wire name moved");
        let bytes = manifest_with("runtime_abi", wire);
        let manifest: CapsuleManifest = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("CapsuleManifest refused {}: {error}", rule.wire));
        let said = manifest.validate();
        results.push(format!("{}: {said:?} (needs {})", rule.wire, rule.needs));
        if said.as_ref().err().map(String::as_str) != Some(rule.reason) {
            wrong.push(format!(
                "{}: validate() said {said:?}, not its own refusal {:?}",
                rule.wire, rule.reason
            ));
        }
    }
    println!("{NO_ABI}");
    for line in &results {
        println!("  {line}");
    }
    assert!(
        wrong.is_empty(),
        "an ABI was not refused for its own reason, so the gap may be wrong: {wrong:?}"
    );

    // With no runtime_abi the manifest validates
    // (`lab_manifest_passes_runtime_validate`), but both run paths refuse a
    // `type` `wasm` capsule that is not a Component: run_cmd.rs:51-57 and
    // capsule_cmd.rs:267-273, on `!manifest.is_component_capsule()`.
    let bare: CapsuleManifest =
        serde_json::from_slice(CAPSULE_MANIFEST).expect("CapsuleManifest parses capsule.json");
    assert!(
        bare.runtime_abi.is_none() && !bare.is_component_capsule(),
        "this capsule's manifest must stay bare (no runtime_abi, not a Component): runtime_abi {:?}",
        bare.runtime_abi
    );
}

#[test]
fn an_unknown_manifest_field_is_refused_by_name() {
    let bytes = manifest_with("lab_imports", Value::Array(Vec::new()));

    let parsed = serde_json::from_slice::<CapsuleManifest>(&bytes);
    let error = match parsed {
        Ok(_) => panic!("CapsuleManifest accepted an invented field lab_imports"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("unknown field `lab_imports`"),
        "the Runtime's refusal does not name lab_imports: {error}"
    );

    let tmp = TempDir::new("runtime-abi-unknown-field");
    let bundle = tmp.path().join("bundle");
    fs::create_dir_all(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), &bytes).expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), MODULE).expect("write capsule.wasm");
    match bundle_identity(&bundle) {
        Err(Refusal::ManifestUnparsed(reason)) => assert_eq!(
            reason, error,
            "bundle_identity's manifest-parse reason is not the Runtime's"
        ),
        other => panic!(
            "bundle_identity did not refuse the bundle with its manifest-parse reason: {other:?}"
        ),
    }
}
