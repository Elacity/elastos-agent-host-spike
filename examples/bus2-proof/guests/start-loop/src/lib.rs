//! A guest whose start-up never ends. `wit-component` runs an exported
//! `_initialize` as the core start function, during instantiation, before
//! `lifecycle.run` can be called.

wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

use elastos::bus::types::{BusError, Event};

#[no_mangle]
pub extern "C" fn _initialize() {
    let mut count: u64 = 0;
    loop {
        count = core::hint::black_box(count.wrapping_add(1));
    }
}

struct StartLoop;

impl exports::elastos::bus::lifecycle::Guest for StartLoop {
    async fn run(_events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        Ok(())
    }
}

export!(StartLoop);
