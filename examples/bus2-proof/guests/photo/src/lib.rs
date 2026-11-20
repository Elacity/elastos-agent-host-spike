//! The photo guest: it shows one photo it is pointed at.
//!
//! The host sends the photo's URI as a `message` event. The guest asks for a
//! read grant on exactly that URI, reads it through `providers.invoke`, and
//! uses the bytes only once the read's trailing future says `ok`. It asks for
//! at most its manifest's `photo.max_bytes`, and refuses more than that even
//! if more arrives.
//!
//! Before it draws anything, it needs a credential from its pinned publisher
//! for exactly the bytes it read. It can only refuse; it never grants.

wit_bindgen::generate!({ path: "../../wit", world: "product-capsule-v2" });

include!(concat!(env!("OUT_DIR"), "/manifest.rs"));

use elastos::bus::types::{BusError, Event, InvokeRequest};
use elastos::bus::{capabilities, credentials, providers, ui};
use sha2::{Digest, Sha256};
use wit_bindgen::StreamResult;

/// Bytes the guest asks for per read of the stream.
const READ_BUFFER: usize = 64 * 1024;
const MEDIA_TYPE: &str = "application/vnd.elastos.ui+json;v=0";
/// The domain tag at the start of every signed credential message.
const CREDENTIAL_TAG: &str = "elastos:bus2-proof:credential:v1";

struct Photo;

/// A photo read whole, and the grant it was read with.
struct Read {
    grant: String,
    bytes: Vec<u8>,
}

/// The whole object, or a refusal. Nothing partial is ever returned.
async fn read_photo(uri: &str) -> Result<Read, BusError> {
    let grant = capabilities::request(
        uri.to_string(),
        vec!["read".to_string()],
        "show this photo".to_string(),
    )
    .await?;
    let request = InvokeRequest {
        resource: uri.to_string(),
        operation: "read".to_string(),
        grant: Some(grant.id.clone()),
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
    Ok(Read {
        grant: grant.id,
        bytes,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The message a credential's body signs: the domain tag, the kind and the
/// subject's SHA-256 (hex), one per line.
fn signed_message(kind: &str, subject_sha256: &str) -> String {
    format!("{CREDENTIAL_TAG}\n{kind}\n{subject_sha256}")
}

/// Needs a credential of the pinned kind, from the pinned publisher, signed
/// by the pinned key (whatever `signer` says), for exactly these bytes.
fn check_credential(bytes: &[u8]) -> Result<(), BusError> {
    let subject = hex(&Sha256::digest(bytes));
    let presented = credentials::presented();
    let mut candidates = presented
        .iter()
        .filter(|credential| credential.kind == CREDENTIAL_KIND);
    let Some(credential) = candidates.next() else {
        return Err(BusError::Denied(format!(
            "no {CREDENTIAL_KIND} credential was presented"
        )));
    };
    if candidates.next().is_some() {
        return Err(BusError::Denied(format!(
            "more than one {CREDENTIAL_KIND} credential was presented"
        )));
    }
    if credential.signer != PINNED_SIGNER {
        return Err(BusError::Denied(format!(
            "the credential's signer {} is not the pinned publisher",
            credential.signer
        )));
    }
    if credential.subject_sha256 != subject {
        return Err(BusError::Denied(
            "the credential is for other bytes than were read".to_string(),
        ));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&PINNED_KEY)
        .map_err(|_| BusError::Internal("the pinned key is not a key".to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&credential.body)
        .map_err(|_| BusError::Denied("the credential's body is not a signature".to_string()))?;
    key.verify_strict(
        signed_message(CREDENTIAL_KIND, &subject).as_bytes(),
        &signature,
    )
    .map_err(|_| BusError::Denied("the credential is not signed by the pinned key".to_string()))
}

/// One frame: the photo, by its grant (never its bytes or URI), and a line
/// of text.
async fn draw(read: &Read) -> Result<(), BusError> {
    if read.grant.contains(['"', '\\']) {
        return Err(BusError::Invalid(
            "a grant id the guest cannot quote".to_string(),
        ));
    }
    let document = format!(
        r#"{{"frame":[{{"image":{{"grant":"{}"}}}},{{"text":"{} bytes"}}]}}"#,
        read.grant,
        read.bytes.len()
    );
    ui::present(MEDIA_TYPE.to_string(), document.into_bytes()).await
}

impl exports::elastos::bus::lifecycle::Guest for Photo {
    async fn run(mut events: wit_bindgen::StreamReader<Event>) -> Result<(), BusError> {
        while let Some(event) = events.next().await {
            if let Event::Message(uri) = event {
                let uri = String::from_utf8(uri)
                    .map_err(|_| BusError::Invalid("a photo URI is UTF-8".to_string()))?;
                let read = read_photo(&uri).await?;
                // After the read, before any frame.
                check_credential(&read.bytes)?;
                draw(&read).await?;
            }
        }
        Ok(())
    }
}

export!(Photo);
