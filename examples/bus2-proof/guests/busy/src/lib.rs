//! A guest that never yields: its `run` loops forever without awaiting.

wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

use elastos::bus::types::{BusError, Event};

struct Busy;

impl exports::elastos::bus::lifecycle::Guest for Busy {
    async fn run(_events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        let mut count: u64 = 0;
        loop {
            count = core::hint::black_box(count.wrapping_add(1));
        }
    }
}

export!(Busy);
