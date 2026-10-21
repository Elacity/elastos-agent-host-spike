//! A resident guest: it handles events until the host closes its events
//! stream, then returns.
//!
//! Test controls, sent as `message` events, so one guest covers each ending:
//! - `linger`: after the close, wait instead of returning;
//! - `fail-on-stop`: after the close, return an error;
//! - `return-now`: return at once, before any close.
//!
//! `stop-requested` is ignored: closing the stream is the one way to stop.

wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

use elastos::bus::types::{BusError, Event};
use elastos::bus::{clock, ui};

const MEDIA_TYPE: &str = "application/vnd.elastos.ui+json;v=0";

struct Resident;

async fn draw(text: &str) -> Result<(), BusError> {
    // `text` is made here and holds no quote or backslash.
    let document = format!(r#"{{"frame":[{{"text":"{text}"}}]}}"#);
    ui::present(MEDIA_TYPE.to_string(), document.into_bytes()).await
}

impl exports::elastos::bus::lifecycle::Guest for Resident {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        let (mut seen, mut linger, mut fail) = (0u32, false, false);
        while let Some(event) = events.next().await {
            match event {
                Event::Message(bytes) if bytes == b"linger" => linger = true,
                Event::Message(bytes) if bytes == b"fail-on-stop" => fail = true,
                Event::Message(bytes) if bytes == b"return-now" => return Ok(()),
                Event::StopRequested | Event::GrantRevoked(_) => {}
                Event::UserInput(bytes) | Event::Message(bytes) => {
                    seen += 1;
                    draw(&format!("event {seen}: {} bytes", bytes.len())).await?;
                }
            }
        }
        if linger {
            clock::sleep_until_ms(u64::MAX).await;
        }
        if fail {
            return Err(BusError::Internal("asked to fail when stopped".to_string()));
        }
        Ok(())
    }
}

export!(Resident);
