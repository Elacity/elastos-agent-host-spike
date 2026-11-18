//! Source for `../v2-invoke-body.component.wasm`. Build this crate for
//! `wasm32-unknown-unknown` in release mode, then encode its core module with
//! `wit-component` 0.254.2 `ComponentEncoder` (module plus validation).
//! The guest requires the host to close a refused invoke body.

wit_bindgen::generate!({ path: "../../../../wit-bus-v2", world: "product-capsule-v2" });

use elastos::bus::providers;
use elastos::bus::types::{BusError, Event, InvokeRequest};

struct InvokeBody;

impl exports::elastos::bus::lifecycle::Guest for InvokeBody {
    async fn run(_events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        let (mut writer, reader) = wit_stream::new::<u8>();
        let request = InvokeRequest {
            resource: "elastos://test/body".into(),
            operation: "read".into(),
            grant: None,
            params: Vec::new(),
        };
        if !matches!(
            providers::invoke(request, Some(reader)).await,
            Err(BusError::Unavailable(_))
        ) {
            return Err(BusError::Internal("invoke did not refuse the body".into()));
        }
        if writer.write_one(7).await != Some(7) {
            return Err(BusError::Internal(
                "the refused body writer stayed open".into(),
            ));
        }
        Ok(())
    }
}

export!(InvokeBody);
