//! Shared chat protocol logic — signing, verification gating, nick binding, dedup.
//!
//! This module owns the chat protocol contract. All chat surfaces (native,
//! WASM, microVM, agent) must use these functions for protocol decisions.
//! Transport-specific operations (calling DID sign/verify, gossip send/recv)
//! stay in each surface's own code.

use sha2::{Digest, Sha256};

/// SHA-256 of "sender_id:ts:content" — the canonical signing payload.
///
/// Used by send (sign this) and receive (verify against this).
/// Every chat surface must use this exact format.
pub fn signing_payload_hex(sender_id: &str, ts: u64, content: &str) -> String {
    let data = format!("{}:{}:{}", sender_id, ts, content);
    hex::encode(Sha256::digest(data.as_bytes()))
}

/// Dedup key for gossip messages.
///
/// Uses SHA-256 of (sender_id, sender_nick, ts, content) to detect
/// duplicate messages. The key includes nick to distinguish messages
/// from different sessions that share the same DID.
pub fn dedup_key(sender_id: &str, sender_nick: &str, ts: u64, content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sender_id.as_bytes());
    hasher.update(sender_nick.as_bytes());
    hasher.update(ts.to_le_bytes());
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Should this message be displayed/acted on?
///
/// Returns false if the message is unverified AND the sender is unknown.
/// Known senders (previously verified nick) are allowed through even if
/// this particular message fails verification (backward compat with older
/// clients that may not sign every message).
pub fn should_accept_message(verified: bool, is_known_sender: bool) -> bool {
    verified || is_known_sender
}

/// Should this message trigger peer attachment?
///
/// Only verified messages should cause the runtime to attach the sender
/// as a room peer. Unverified messages must not influence peer topology.
pub fn should_attach_peer(verified: bool) -> bool {
    verified
}

/// Should this sender's nick→DID binding be recorded?
///
/// Only verified messages should establish nick ownership. This prevents
/// TOFU poisoning where an attacker claims a nick before the real user.
pub fn should_record_nick(verified: bool) -> bool {
    verified
}

/// The Home a direct `gossip_recv` frame names, when it names one.
fn transport_sender(message: &serde_json::Value) -> Option<&str> {
    message
        .get("sender_id")
        .and_then(|value| value.as_str())
        .filter(|sender| !sender.is_empty())
}

/// The DID the sending Home put on its own frame. Not a transport sender.
fn signed_author(message: &serde_json::Value) -> Option<&str> {
    message
        .get("signed_author")
        .and_then(|value| value.as_str())
        .filter(|author| !author.is_empty())
}

/// Author DID for one chat line.
///
/// A direct frame's transport sender and the signed author must be the same
/// Home. A forwarded frame has no transport sender, so the signed author
/// decides. A frame with neither name has no author to check.
pub fn chat_line_author(message: &serde_json::Value) -> Option<&str> {
    match (transport_sender(message), signed_author(message)) {
        (Some(transport), Some(author)) if transport == author => Some(author),
        (Some(transport), None) => Some(transport),
        (None, Some(author)) => Some(author),
        _ => None,
    }
}

/// A verified chat line. `transport_sender` is set only for a direct delivery
/// from `author`. A forwarded line has no claimed transport sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatDelivery<'a> {
    pub author: &'a str,
    pub transport_sender: Option<&'a str>,
}

/// Deliver a chat line only after its signature has been checked.
/// An unverified line is not delivered.
pub fn chat_delivery<'a>(
    message: &'a serde_json::Value,
    verified: bool,
) -> Option<ChatDelivery<'a>> {
    if !verified {
        return None;
    }
    let author = chat_line_author(message)?;
    let transport_sender = transport_sender(message).filter(|sender| *sender == author);
    Some(ChatDelivery {
        author,
        transport_sender,
    })
}

/// Author DID for a presence announcement.
///
/// `envelope_did` is the DID inside the signed presence body. A direct
/// transport sender must name that DID. A signed-author claim, when the
/// frame has one, must name it too. A forwarded frame can carry only the
/// envelope DID; the signature still has to verify against it.
pub fn presence_author<'a>(
    message: &'a serde_json::Value,
    envelope_did: &'a str,
) -> Option<&'a str> {
    if envelope_did.is_empty() {
        return None;
    }
    if let Some(transport) = transport_sender(message) {
        if transport != envelope_did {
            return None;
        }
    }
    if let Some(author) = signed_author(message) {
        if author != envelope_did {
            return None;
        }
    }
    Some(envelope_did)
}

/// Check if a message is from the same chat instance (should be skipped as echo).
///
/// Requires both DID and session_id to match. On a shared runtime, multiple
/// capsules share the same DID but have different session IDs.
pub fn is_own_message(
    self_did: &str,
    self_session_id: &str,
    sender_did: &str,
    sender_session_id: Option<&str>,
) -> bool {
    if self_did.is_empty() || sender_did != self_did {
        return false;
    }
    sender_session_id
        .filter(|s| !s.is_empty())
        .is_some_and(|sid| sid == self_session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_payload_deterministic() {
        let h1 = signing_payload_hex("did:key:zAlice", 1000, "hello");
        let h2 = signing_payload_hex("did:key:zAlice", 1000, "hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn signing_payload_differs_on_any_field() {
        let base = signing_payload_hex("did:key:zAlice", 1000, "hello");
        assert_ne!(base, signing_payload_hex("did:key:zBob", 1000, "hello"));
        assert_ne!(base, signing_payload_hex("did:key:zAlice", 1001, "hello"));
        assert_ne!(base, signing_payload_hex("did:key:zAlice", 1000, "world"));
    }

    #[test]
    fn dedup_key_deterministic() {
        let k1 = dedup_key("did:key:zAlice", "alice", 1000, "hello");
        let k2 = dedup_key("did:key:zAlice", "alice", 1000, "hello");
        assert_eq!(k1, k2);
    }

    #[test]
    fn dedup_key_includes_nick() {
        let k1 = dedup_key("did:key:zShared", "alice", 1000, "hello");
        let k2 = dedup_key("did:key:zShared", "bob", 1000, "hello");
        assert_ne!(k1, k2, "different nicks must produce different dedup keys");
    }

    #[test]
    fn accept_message_gate() {
        assert!(
            should_accept_message(true, false),
            "verified unknown = accept"
        );
        assert!(should_accept_message(true, true), "verified known = accept");
        assert!(
            should_accept_message(false, true),
            "unverified known = accept"
        );
        assert!(
            !should_accept_message(false, false),
            "unverified unknown = reject"
        );
    }

    #[test]
    fn own_message_detection() {
        assert!(is_own_message("did:key:z1", "s1", "did:key:z1", Some("s1")));
        assert!(!is_own_message(
            "did:key:z1",
            "s1",
            "did:key:z1",
            Some("s2")
        ));
        assert!(!is_own_message(
            "did:key:z1",
            "s1",
            "did:key:z2",
            Some("s1")
        ));
        assert!(!is_own_message("did:key:z1", "s1", "did:key:z1", None));
        assert!(!is_own_message("", "s1", "did:key:z1", Some("s1"))); // empty self
    }

    #[test]
    fn forwarded_chat_line_names_signed_author_without_transport_sender() {
        let forwarded = serde_json::json!({
            "signed_author": "did:key:zAlice",
            "content": "hello",
            "ts": 1000,
            "signature": "sig",
        });
        assert_eq!(chat_line_author(&forwarded), Some("did:key:zAlice"));
        assert_eq!(
            chat_delivery(&forwarded, true),
            Some(ChatDelivery {
                author: "did:key:zAlice",
                transport_sender: None,
            })
        );
        assert!(chat_delivery(&forwarded, false).is_none());
        let unnamed = serde_json::json!({"content": "hello", "signature": "sig"});
        assert!(chat_line_author(&unnamed).is_none());
        assert!(chat_delivery(&unnamed, true).is_none());
    }

    #[test]
    fn direct_chat_refuses_author_transport_mismatch() {
        let mismatch = serde_json::json!({
            "sender_id": "did:key:zBob",
            "signed_author": "did:key:zAlice",
        });
        assert!(chat_line_author(&mismatch).is_none());
        let direct = serde_json::json!({"sender_id": "did:key:zAlice"});
        assert_eq!(
            chat_delivery(&direct, true),
            Some(ChatDelivery {
                author: "did:key:zAlice",
                transport_sender: Some("did:key:zAlice"),
            })
        );
    }

    #[test]
    fn forwarded_presence_names_envelope_did() {
        let forwarded = serde_json::json!({"content": "{}"});
        assert_eq!(
            presence_author(&forwarded, "did:key:zAlice"),
            Some("did:key:zAlice")
        );
        let claimed = serde_json::json!({"signed_author": "did:key:zAlice"});
        assert_eq!(
            presence_author(&claimed, "did:key:zAlice"),
            Some("did:key:zAlice")
        );
        let mismatch = serde_json::json!({"sender_id": "did:key:zBob"});
        assert!(presence_author(&mismatch, "did:key:zAlice").is_none());
        let forged_author = serde_json::json!({"signed_author": "did:key:zBob"});
        assert!(presence_author(&forged_author, "did:key:zAlice").is_none());
        assert!(presence_author(&forwarded, "").is_none());
    }

    #[test]
    fn attach_and_nick_require_verification() {
        assert!(should_attach_peer(true));
        assert!(!should_attach_peer(false));
        assert!(should_record_nick(true));
        assert!(!should_record_nick(false));
    }
}
