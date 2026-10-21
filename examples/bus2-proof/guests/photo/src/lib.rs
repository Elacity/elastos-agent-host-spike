wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

use elastos::bus::types::{BusError, Event};

struct Photo;

impl exports::elastos::bus::lifecycle::Guest for Photo {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        while let Some(_event) = events.next().await {}
        Ok(())
    }
}

export!(Photo);
