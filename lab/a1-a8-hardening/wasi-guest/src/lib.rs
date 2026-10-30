//! One source, two builds. The default build has the same world as the
//! agent-host and the probe. The `wasi-env` build adds exactly one import,
//! `wasi:cli/environment@0.2.0`, and calls it so the import stays in the
//! component. The shared build script has no feature input; the test selects
//! `wasi-env` with `--cfg feature="wasi-env"`.

#[cfg(all(target_arch = "wasm32", not(feature = "wasi-env")))]
wit_bindgen::generate!({
    path: "../../../elastos/wit",
    world: "product-capsule-v1",
});

#[cfg(all(target_arch = "wasm32", feature = "wasi-env"))]
wit_bindgen::generate!({
    path: ["../../../elastos/wit", "wit"],
    inline: "
        package lab:a1-wasi-guest;

        world wasi-guest {
            include elastos:bus/product-capsule-v1@1.0.0;
            import wasi:cli/environment@0.2.0;
        }
    ",
    world: "wasi-guest",
    generate_all,
});

#[cfg(target_arch = "wasm32")]
struct Guest;

#[cfg(target_arch = "wasm32")]
impl exports::elastos::bus::lifecycle::Guest for Guest {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        #[cfg(feature = "wasi-env")]
        {
            // Reached only if admission and linking both let the import through.
            let entries = wasi::cli::environment::get_environment().len();
            Err(elastos::bus::types::BusError::Denied(format!(
                "a1-wasi-guest ran with {entries} host environment entries"
            )))
        }
        #[cfg(not(feature = "wasi-env"))]
        {
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
export!(Guest);
