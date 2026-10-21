//! The photo guest: it shows one photo it is pointed at.
//!
//! The host sends the photo's URI as a `message` event. The guest asks for a
//! read grant on exactly that URI, reads it through `providers.invoke`, and
//! uses the bytes only once the read's trailing future says `ok`. It asks for
//! at most its manifest's `photo.max_bytes`, and refuses more than that even
//! if more arrives.

wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

include!(concat!(env!("OUT_DIR"), "/manifest.rs"));

use elastos::bus::types::{BusError, Event, InvokeRequest};
use elastos::bus::{capabilities, providers};
use wit_bindgen::StreamResult;

/// Bytes the guest asks for per read of the stream.
const READ_BUFFER: usize = 64 * 1024;

struct Photo;

/// The whole object, or a refusal. Nothing partial is ever returned.
async fn read_photo(uri: &str) -> Result<Vec<u8>, BusError> {
    let grant = capabilities::request(
        uri.to_string(),
        vec!["read".to_string()],
        "show this photo".to_string(),
    )
    .await?;
    let request = InvokeRequest {
        resource: uri.to_string(),
        operation: "read".to_string(),
        grant: Some(grant.id),
        params: format!(r#"{{"max_bytes":{MAX_PHOTO_BYTES}}}"#).into_bytes(),
    };
    let (_status, mut stream, trailer) = providers::invoke(request, None).await?;
    let mut bytes = Vec::new();
    loop {
        let (result, chunk) = stream.read(Vec::with_capacity(READ_BUFFER)).await;
        if bytes.len() + chunk.len() > MAX_PHOTO_BYTES {
            return Err(BusError::Invalid(format!(
                "more than the {MAX_PHOTO_BYTES} bytes asked for arrived; none are used"
            )));
        }
        bytes.extend_from_slice(&chunk);
        match result {
            StreamResult::Complete(_) => continue,
            StreamResult::Dropped => break,
            StreamResult::Cancelled => {
                return Err(BusError::Unavailable("the read was cancelled".to_string()))
            }
        }
    }
    // Only the trailing future says whether these bytes are the object.
    trailer.await?;
    Ok(bytes)
}

impl exports::elastos::bus::lifecycle::Guest for Photo {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        while let Some(event) = events.next().await {
            if let Event::Message(uri) = event {
                let uri = String::from_utf8(uri)
                    .map_err(|_| BusError::Invalid("a photo URI is UTF-8".to_string()))?;
                let _photo = read_photo(&uri).await?;
            }
        }
        Ok(())
    }
}

export!(Photo);
