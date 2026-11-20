//! Proof 5: only elastos:bus/*@2.0.0 imports are admitted.
mod common;

use bus2_host::admission::{admit, check_imports, V2_INTERFACES};

fn refused(bytes: &[u8]) -> &'static str {
    let refusal = check_imports(bytes).expect_err("expected a refusal");
    println!("refused: {refusal}");
    refusal.code()
}

#[test]
fn the_real_guest_imports_only_bus_v2() {
    let engine = bus2_host::engine().unwrap();
    let bytes = common::guest("bus2_photo_guest");
    let imports = check_imports(&bytes).unwrap();
    assert!(!imports.is_empty());
    for name in &imports {
        let interface = name
            .strip_prefix("elastos:bus/")
            .and_then(|rest| rest.strip_suffix("@2.0.0"))
            .unwrap_or_else(|| panic!("{name}"));
        assert!(V2_INTERFACES.contains(&interface), "{name}");
    }
    admit(&engine, &bytes).unwrap();
    admit(&engine, &common::fixture("bus-only.wat")).unwrap();
}

#[test]
fn any_wasi_import_is_refused() {
    assert_eq!(refused(&common::fixture("wasi-import.wat")), "wasi_import");
    // admit checks before it compiles; the fixture itself would compile.
    let engine = bus2_host::engine().unwrap();
    let refusal = admit(&engine, &common::fixture("wasi-import.wat")).unwrap_err();
    assert_eq!(refusal.code(), "wasi_import");
}

#[test]
fn bus_v1_and_v2_together_are_refused() {
    assert_eq!(
        refused(&common::fixture("mixed-v1-v2.wat")),
        "mixed_bus_versions"
    );
}

#[test]
fn anything_outside_bus_v2_is_refused() {
    for fixture in [
        "v1-only.wat",
        "other-v2-version.wat",
        "other-package.wat",
        "plain-func.wat",
    ] {
        assert_eq!(
            refused(&common::fixture(fixture)),
            "outside_bus_v2",
            "{fixture}"
        );
    }
}

#[test]
fn a_bus_v2_interface_outside_the_world_is_refused() {
    assert_eq!(
        refused(&common::fixture("unknown-interface.wat")),
        "unknown_bus_interface"
    );
}

#[test]
fn core_modules_are_refused() {
    assert_eq!(
        refused(&common::fixture("core-module-import.wat")),
        "core_module_import"
    );
    assert_eq!(
        refused(&common::fixture("core-module.wat")),
        "not_a_component"
    );
    // The guest's own core module, before componentizing, is not a guest.
    let core = std::fs::read(
        common::root().join("target/wasm32-unknown-unknown/release/bus2_photo_guest.wasm"),
    )
    .unwrap();
    assert_eq!(refused(&core), "not_a_component");
}

#[test]
fn bytes_that_do_not_parse_are_refused() {
    assert_eq!(refused(b"not wasm"), "malformed");
    let engine = bus2_host::engine().unwrap();
    assert_eq!(
        admit(&engine, b"\0asm\x0d\0\x01\0garbage")
            .unwrap_err()
            .code(),
        "malformed"
    );
}
