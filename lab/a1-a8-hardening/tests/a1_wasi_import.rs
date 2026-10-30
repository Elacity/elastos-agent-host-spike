//! M1 A1: Runtime admission refuses a component that imports a WASI interface
//! outside its elastos:bus allowlist, before the component starts.

use a1_a8_hardening::{build_component, component_imports, sha256, Home, Operator};
use a1_a8_hardening::{runtime, RUNTIME_ALLOWLIST};
use std::time::Duration;

const GUEST: &str = "lab/a1-a8-hardening/wasi-guest";
const INPUTS: &[&str] = &["Cargo.toml", "Cargo.lock", "capsule.json", "src", "wit"];
const WASI_IMPORT: &str = "wasi:cli/environment@0.2.0";
const REFUSAL: &str = "Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0";
const ADMITTED: &str = "[run] Component capsule 'a1-wasi-guest' exited";
const BOUND: Duration = Duration::from_secs(60);

#[test]
fn wasi_import_is_refused_at_admission() {
    let wasi = build_component(
        GUEST,
        INPUTS,
        "a1-wasi-env",
        "-Dwarnings --cfg feature=\"wasi-env\"",
        &[],
    );
    let control = build_component(GUEST, INPUTS, "a1-control", "-Dwarnings", &[]);
    let wasi_imports = component_imports(&wasi.bytes);
    let control_imports = component_imports(&control.bytes);
    println!("a1 runtime: elastos sha256 {}", runtime().sha256);
    println!(
        "a1 wasi build: sha256 {} imports {wasi_imports:?}",
        sha256(&wasi.bytes)
    );
    println!(
        "a1 control build: sha256 {} imports {control_imports:?}",
        sha256(&control.bytes)
    );
    assert!(
        wasi_imports.iter().any(|name| name == WASI_IMPORT),
        "the refused build must import {WASI_IMPORT}"
    );
    assert!(
        control_imports
            .iter()
            .all(|name| RUNTIME_ALLOWLIST.contains(&name.as_str())),
        "the control build must import only allowlisted elastos:bus interfaces"
    );
    assert_eq!(
        wasi.manifest, control.manifest,
        "both builds share one manifest"
    );

    let home = Home::new();
    let refused_dir = home.stage("wasi-env", &wasi.bytes, &wasi.manifest);
    let control_dir = home.stage("control", &control.bytes, &control.manifest);
    let operator = Operator::start(&home);
    let refused = home.run(&refused_dir, BOUND);
    let admitted = home.run(&control_dir, BOUND);
    operator.stop();
    println!(
        "a1 refused run: exit:{:?} refusal_line:{:?}",
        refused.status.and_then(|status| status.code()),
        refused.line_with("Error:")
    );
    println!(
        "a1 control run: exit:{:?} admitted_line:{:?}",
        admitted.status.and_then(|status| status.code()),
        admitted.line_with("exited")
    );
    assert!(
        refused.status.is_some() && !refused.exited_ok() && refused.has_line(REFUSAL),
        "expected nonzero exit and the exact admission refusal; stderr:\n{}",
        refused.stderr
    );
    assert!(
        refused.line_with("Component capsule denied").is_none()
            && refused.line_with("exited").is_none(),
        "the refused component must not start; stderr:\n{}",
        refused.stderr
    );
    assert!(
        admitted.exited_ok() && admitted.has_line(ADMITTED),
        "the control build must be admitted and exit; stderr:\n{}",
        admitted.stderr
    );
    home.finish();
}
