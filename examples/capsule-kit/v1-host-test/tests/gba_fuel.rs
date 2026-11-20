//! Fuel of the product-ROM open: the built GBA core runs once under the shared
//! harness's own fuel runner, with the Runtime's listing and a 1,933,560-byte
//! ROM made in a temporary directory. The number is printed and must stay
//! under a tenth of the 100,000,000 budget (ruling r3 §8 A7: a measurement,
//! not a plant).

use std::path::{Path, PathBuf};

use capsule_v1_host_test::{measure, Bridge};
use serde_json::json;

const ROM_BYTES: usize = 1_933_560;
const FUEL_CEILING: u64 = 10_000_000;

fn core_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../gba-viewer/core")
}

/// A temporary directory removed when the test ends.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_product_rom_open_stays_well_under_the_fuel_budget() {
    let core = core_dir();
    let component = core.join("gba-viewer-core.component.wasm");
    assert!(
        component.is_file(),
        "{} is missing; run examples/gba-viewer/core/build.sh first",
        component.display()
    );

    let fixture =
        TempDir(std::env::temp_dir().join(format!("gba-core-fuel-{}", std::process::id())));
    std::fs::create_dir_all(&fixture.0).unwrap();
    let rom_path = fixture.0.join("ucity.gba");
    std::fs::write(&rom_path, vec![0u8; ROM_BYTES]).unwrap();
    let rom = std::fs::read(&rom_path).unwrap();
    assert_eq!(rom.len(), ROM_BYTES);

    let listing = json!({
        "schema": "elastos.launch.content-listing/v1",
        "files": [{ "path": "ucity.gba", "size": ROM_BYTES }],
    })
    .to_string()
    .into_bytes();
    let mut bridge = Bridge {
        launch: true,
        ..Bridge::default()
    };
    bridge.put("elastos://launch/content/", listing);
    bridge.put("elastos://launch/content/ucity.gba", rom);
    bridge.allow("elastos://launch/content/*", "read");
    bridge.allow("elastos://launch/output/*", "write");

    let (outcome, used) =
        measure::run(bridge, &component, "gba-viewer-core", measure::RUNTIME_FUEL);
    println!("fuel used: {used}");
    outcome.expect("the product-ROM open finishes");
    assert!(
        used < FUEL_CEILING,
        "fuel used: {used}, ceiling {FUEL_CEILING}"
    );
}
