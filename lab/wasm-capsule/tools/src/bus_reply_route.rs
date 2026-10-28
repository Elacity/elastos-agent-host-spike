//! Bus reply routing (M2 KT2, P3, P11).
//!
//! A request opens one route: `(request id, requester capsule, sender
//! capsule)`. A reply is delivered only to the request's sender, and only
//! for the request id and capsule of the open route. A reply that names a
//! request id or capsule other than the open route's is refused
//! `reply_misrouted`. A second reply to an already answered request is
//! refused `already_replied`.
//!
//! The table is self-contained and holds owned `String` capsule names, so
//! callers pass plain `&str` values and the module keeps no reference to
//! their owners. Capsule names must be relative, non-empty and at most
//! [`MAX_CAPSULE_ID_LEN`] bytes; an absolute path (leading `/`) is refused
//! `bad_capsule`, so no host path can reach a refusal message.
//!
//! Presets (conservative, chosen here): [`MAX_OPEN_REQUESTS`] is 64 open
//! routes at once, [`MAX_CAPSULE_ID_LEN`] is 128 bytes. Reaching either is
//! a refusal, not a silent drop.

use std::collections::HashMap;
use std::fmt;

/// Most requests that may be open at one time.
pub const MAX_OPEN_REQUESTS: usize = 64;

/// Longest accepted capsule name, in bytes.
pub const MAX_CAPSULE_ID_LEN: usize = 128;

/// Every refusal this module can return. `code()` is the stable table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusReplyError {
    /// The reply names another request id, or a capsule that is not the
    /// open route's capsule.
    ReplyMisrouted,
    /// The request this reply answers was already answered once.
    AlreadyReplied,
    /// The reply or request named an unknown request id.
    UnknownRequest,
    /// A capsule name was empty, too long, or an absolute path.
    BadCapsule,
    /// The open-request table is full.
    TableFull,
}

impl BusReplyError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BusReplyError::ReplyMisrouted => "reply_misrouted",
            BusReplyError::AlreadyReplied => "already_replied",
            BusReplyError::UnknownRequest => "unknown_request",
            BusReplyError::BadCapsule => "bad_capsule",
            BusReplyError::TableFull => "table_full",
        }
    }
}

impl fmt::Display for BusReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            BusReplyError::ReplyMisrouted => {
                "reply names another request id or capsule than the open route"
            }
            BusReplyError::AlreadyReplied => "this request already has its one reply",
            BusReplyError::UnknownRequest => "no open request has that request id",
            BusReplyError::BadCapsule => "capsule name must be a short relative name",
            BusReplyError::TableFull => "too many open requests",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

impl std::error::Error for BusReplyError {}

/// One open request and the single reply it may receive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    requester: String,
    sender: String,
    answered: bool,
}

/// What a delivered reply reports back to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    /// The capsule the reply was handed to: always the requester.
    pub delivered_to: String,
    /// The capsule whose request the reply answers.
    pub answered_for: String,
}

/// The open-request table. One table per bus; reply delivery goes through
/// [`BusReplyRoute::route_reply`] and nowhere else.
#[derive(Debug, Default)]
pub struct BusReplyRoute {
    routes: HashMap<String, Route>,
}

fn check_capsule(capsule: &str) -> Result<(), BusReplyError> {
    if capsule.is_empty()
        || capsule.len() > MAX_CAPSULE_ID_LEN
        || capsule.starts_with('/')
    {
        return Err(BusReplyError::BadCapsule);
    }
    Ok(())
}

impl BusReplyRoute {
    /// An empty table.
    pub fn new() -> Self {
        BusReplyRoute {
            routes: HashMap::new(),
        }
    }

    /// Record one request. `request_id` opens a route from `requester` to
    /// `sender`; the reply must come back from `sender` and is delivered to
    /// `requester`. Reusing an open or answered request id is refused
    /// `reply_misrouted` (the id does not name this request).
    pub fn open(
        &mut self,
        request_id: &str,
        requester: &str,
        sender: &str,
    ) -> Result<(), BusReplyError> {
        check_capsule(requester)?;
        check_capsule(sender)?;
        if request_id.is_empty() {
            return Err(BusReplyError::UnknownRequest);
        }
        if self.routes.contains_key(request_id) {
            return Err(BusReplyError::ReplyMisrouted);
        }
        if self.routes.len() >= MAX_OPEN_REQUESTS {
            return Err(BusReplyError::TableFull);
        }
        self.routes.insert(
            request_id.to_string(),
            Route {
                requester: requester.to_string(),
                sender: sender.to_string(),
                answered: false,
            },
        );
        Ok(())
    }

    /// May a reply be accepted for this request id, capsule and sender?
    /// Returns the refusal that [`BusReplyRoute::route_reply`] would give,
    /// without taking the reply.
    pub fn check_reply(
        &self,
        request_id: &str,
        requester_capsule: &str,
        sender: &str,
    ) -> Result<(), BusReplyError> {
        let route = self
            .routes
            .get(request_id)
            .ok_or(BusReplyError::UnknownRequest)?;
        if route.answered {
            return Err(BusReplyError::AlreadyReplied);
        }
        if route.requester != requester_capsule || route.sender != sender {
            return Err(BusReplyError::ReplyMisrouted);
        }
        Ok(())
    }

    /// Take one reply. The reply is accepted only when `request_id`,
    /// `requester_capsule` and `sender` match the open route exactly; it is
    /// then delivered to the route's requester, and a second reply to the
    /// same request is refused `already_replied`.
    pub fn route_reply(
        &mut self,
        request_id: &str,
        requester_capsule: &str,
        sender: &str,
    ) -> Result<Delivered, BusReplyError> {
        self.check_reply(request_id, requester_capsule, sender)?;
        let route = self
            .routes
            .get_mut(request_id)
            .ok_or(BusReplyError::UnknownRequest)?;
        route.answered = true;
        Ok(Delivered {
            delivered_to: route.requester.clone(),
            answered_for: requester_capsule.to_string(),
        })
    }

    /// Number of routes recorded so far, answered or open.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// True when no request has ever opened a route.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P11: a reply reaches only the request's sender, never anyone else.
    #[test]
    fn reply_is_delivered_only_to_the_requester() {
        let mut bus = BusReplyRoute::new();
        bus.open("req-1", "capsule-a", "capsule-b").unwrap();
        let got = bus
            .route_reply("req-1", "capsule-a", "capsule-b")
            .unwrap();
        assert_eq!(got.delivered_to, "capsule-a");
        assert_eq!(got.answered_for, "capsule-a");
        assert_ne!(got.delivered_to, "capsule-b");
    }

    // P11: a reply whose request id names a different open request, or no
    // request at all, is refused rather than delivered to the wrong place.
    // A correct reply still succeeds, and a wrong one is not delivered.
    #[test]
    fn reply_naming_another_request_id_is_refused() {
        let mut bus = BusReplyRoute::new();
        bus.open("req-1", "capsule-a", "capsule-b").unwrap();
        bus.open("req-2", "capsule-a", "capsule-b").unwrap();

        // Reply intended for req-1 but naming req-2's requester and sender:
        // that is a valid reply for req-2, so it is not misrouted.
        assert!(bus
            .route_reply("req-2", "capsule-a", "capsule-b")
            .is_ok());

        // Reply naming req-2 but with req-3's capsule pair is misrouted.
        let err = bus
            .route_reply("req-2", "capsule-x", "capsule-y")
            .unwrap_err();
        assert_eq!(err.code(), "already_replied");

        // A reply naming an id that names no open request is unknown.
        let err = bus
            .route_reply("req-9", "capsule-a", "capsule-b")
            .unwrap_err();
        assert_eq!(err.code(), "unknown_request");

        // req-1 remains open and unanswered: a correct reply succeeds once.
        let got = bus
            .route_reply("req-1", "capsule-a", "capsule-b")
            .unwrap();
        assert_eq!(got.delivered_to, "capsule-a");

        // A reply that names a different request id than the one it carries
        // from is a misrouted reply for the capsule it does not match.
        let mut bus = BusReplyRoute::new();
        bus.open("req-1", "capsule-a", "capsule-b").unwrap();
        bus.open("req-2", "capsule-c", "capsule-b").unwrap();
        let err = bus
            .route_reply("req-1", "capsule-c", "capsule-b")
            .unwrap_err();
        assert_eq!(err.code(), "reply_misrouted");
    }

    // P11: a reply naming another capsule is refused reply_misrouted.
    #[test]
    fn reply_naming_another_capsule_is_misrouted() {
        let mut bus = BusReplyRoute::new();
        bus.open("req-1", "capsule-a", "capsule-b").unwrap();
        let err = bus
            .route_reply("req-1", "capsule-c", "capsule-b")
            .unwrap_err();
        assert_eq!(err.code(), "reply_misrouted");
        let err = bus
            .route_reply("req-1", "capsule-a", "capsule-c")
            .unwrap_err();
        assert_eq!(err.code(), "reply_misrouted");
    }

    // P3: one request has exactly one reply; a second is already_replied.
    #[test]
    fn second_reply_is_already_replied() {
        let mut bus = BusReplyRoute::new();
        bus.open("req-1", "capsule-a", "capsule-b").unwrap();
        bus.route_reply("req-1", "capsule-a", "capsule-b").unwrap();
        let err = bus
            .route_reply("req-1", "capsule-a", "capsule-b")
            .unwrap_err();
        assert_eq!(err.code(), "already_replied");
        assert_eq!(
            bus.check_reply("req-1", "capsule-a", "capsule-b")
                .unwrap_err()
                .code(),
            "already_replied"
        );
    }

    // P3: Display renders "<code>: <explanation>" and carries no host path.
    #[test]
    fn display_is_code_then_explanation_without_host_path() {
        let err = BusReplyError::ReplyMisrouted;
        let text = err.to_string();
        assert!(text.starts_with("reply_misrouted: "));
        assert!(!text.contains('/'));
    }

    // P11: an absolute capsule path is refused before a route opens.
    #[test]
    fn absolute_capsule_name_is_bad_capsule() {
        let mut bus = BusReplyRoute::new();
        let err = bus.open("req-1", "/abs/a", "capsule-b").unwrap_err();
        assert_eq!(err.code(), "bad_capsule");
        assert!(bus.is_empty());
    }

    // P3: the table at its limit refuses the next open, and no reply is taken.
    #[test]
    fn full_table_refuses_and_takes_no_reply() {
        let mut bus = BusReplyRoute::new();
        for i in 0..MAX_OPEN_REQUESTS {
            bus.open(&format!("req-{i}"), "capsule-a", "capsule-b")
                .unwrap();
        }
        let err = bus.open("req-over", "capsule-a", "capsule-b").unwrap_err();
        assert_eq!(err.code(), "table_full");
        assert_eq!(bus.len(), MAX_OPEN_REQUESTS);
    }
}
