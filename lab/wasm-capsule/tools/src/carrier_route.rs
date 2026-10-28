// Built-by: deepseek-v4.1-flash-1017-ultrafast
//! P2-9: the Runtime stand-in picks the carrier route. A capsule names a CID
//! and the size it needs; the Runtime chooses a route from the permitted
//! descriptors by size fit and put support. A capsule-named route, transport
//! or address is refused `capsule-named-route`. When nothing permitted fits,
//! the fetch fails closed `no-permitted-carrier`; there is no raw-socket or
//! Boson fallback.
//!
//! This module is lab-side and runtime-free: it opens no socket, reads no
//! file and signs nothing. It is self-contained and imports nothing from the
//! crate, so it compiles on the current base without a descriptor module.
//!
//! Principles proven by the tests below:
//! - P3 deterministic and fail-closed: a refusal is an exact reason string,
//!   never a silent fallback.
//! - P15 the Runtime picks carrier routes: a capsule cannot name its own
//!   route/transport/address and cannot reach a raw socket or Boson peer.

/// The steady reason text for a capsule that named its own route, transport
/// or address.
pub const CAPSULE_NAMED_ROUTE: &str = "capsule-named-route";
/// The steady reason text for a fetch where no permitted carrier fits.
pub const NO_PERMITTED_CARRIER: &str = "no-permitted-carrier";
/// The steady reason text for a CID that is not `sha256:` plus 64 hex.
pub const BAD_CID: &str = "bad-cid";

/// A permitted carrier as the Runtime knows it: a name, what it supports, and
/// the largest object it will carry. This is the minimal descriptor seam this
/// module needs; the Runtime supplies the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub name: String,
    pub supports_get: bool,
    pub supports_put: bool,
    pub max_object_bytes: u64,
}

/// What a request needs from a carrier: get always, put when the capsule
/// writes, and the object size it will move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Need {
    pub put: bool,
    pub size: u64,
}

/// True when `d` can serve `need`: size fits within `max_object_bytes` and, if
/// a put is needed, the carrier supports put.
pub fn fits(d: &Descriptor, need: Need) -> bool {
    d.supports_get && need.size <= d.max_object_bytes && (!need.put || d.supports_put)
}

/// Choose the first permitted descriptor, in list order, that fits `need`.
/// Returns `None` when none fits; the caller must fail closed.
pub fn choose(descs: &[Descriptor], need: Need) -> Option<&Descriptor> {
    descs.iter().find(|d| fits(d, need))
}

/// Build a descriptor from the same JSON shape the lab descriptors use. Kept
/// here so this module has no crate dependency; unknown fields are ignored by
/// the simple field scan and malformed input is an error.
pub fn parse_descriptor(json: &str) -> Result<Descriptor, String> {
    fn field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
        let pat = format!("\"{}\":", key);
        let at = json.find(&pat)? + pat.len();
        let rest = json[at..].trim_start();
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        Some(rest[..end].trim().trim_matches('"'))
    }
    let name = field(json, "name").ok_or_else(|| "descriptor missing name".to_string())?;
    let max = field(json, "max_object_bytes")
        .ok_or_else(|| "descriptor missing max_object_bytes".to_string())?
        .parse::<u64>()
        .map_err(|_| "descriptor max_object_bytes not a number".to_string())?;
    let supports = field(json, "supports").unwrap_or("");
    let put = json
        .split("\"put\":")
        .nth(1)
        .map(|s| s.trim_start().starts_with("true"))
        .unwrap_or(false);
    let _ = supports;
    Ok(Descriptor {
        name: name.to_string(),
        supports_get: true,
        supports_put: put,
        max_object_bytes: max,
    })
}

/// A capsule request as it arrives: the CID the capsule wants and the size
/// it believes it needs. `route`, `transport` and `address` are the shortcuts
/// a capsule must NOT take; if any is `Some`, the request is refused
/// `capsule-named-route`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleRequest {
    pub cid: String,
    pub size: u64,
    pub put: bool,
    pub route: Option<String>,
    pub transport: Option<String>,
    pub address: Option<String>,
}

impl CapsuleRequest {
    /// A bare, well-formed request: CID and size only, no route, transport or
    /// address.
    pub fn bare(cid: impl Into<String>, size: u64, put: bool) -> Self {
        Self {
            cid: cid.into(),
            size,
            put,
            route: None,
            transport: None,
            address: None,
        }
    }
}

/// A route refusal. `reason` is stable text safe to log or pin in a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefuse {
    reason: String,
}

impl RouteRefuse {
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for RouteRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "carrier route refused: {}", self.reason)
    }
}

impl std::error::Error for RouteRefuse {}

/// A CID is well formed if it is `sha256:` followed by exactly 64 lowercase
/// hex digits. Parsing the CID here keeps a crafted string from being handed
/// to a store, and matches the shared lab CID shape.
fn parse_cid(cid: &str) -> Result<&str, RouteRefuse> {
    let rest = cid
        .strip_prefix("sha256:")
        .ok_or_else(|| RouteRefuse::new(BAD_CID))?;
    if rest.len() != 64
        || !rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(RouteRefuse::new(BAD_CID));
    }
    Ok(rest)
}

/// Refuse a request that names its own route, transport, or address. This is
/// the Runtime's rule: a capsule may never pin a raw socket or a Boson peer.
///
/// Falsifier: if this let any of the three fields through, a capsule could
/// bypass the Runtime's route choice and reach a raw transport directly.
fn refuse_named(req: &CapsuleRequest) -> Result<(), RouteRefuse> {
    if req.route.is_some() || req.transport.is_some() || req.address.is_some() {
        return Err(RouteRefuse::new(CAPSULE_NAMED_ROUTE));
    }
    Ok(())
}

/// The Runtime's route decision: the chosen descriptor and the ordered names
/// the failover walk should try, chosen first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub chosen: Descriptor,
    pub order: Vec<String>,
}

/// Pick the carrier route for `req` from the permitted `descs`. Refuses a
/// capsule-named route/transport/address and a malformed CID, and refuses
/// `no-permitted-carrier` when no permitted descriptor fits `req.size` and
/// `req.put`. There is no raw-socket or Boson fallback.
///
/// Falsifier: (a) if shortcut fields were read instead of refused, a capsule
/// could pin a path; (b) if `size` or `put` were ignored, an undersized or
/// get-only carrier could be chosen; (c) if a fallback were invented, a fetch
/// that cannot be served would appear to succeed.
pub fn decide_route(
    req: &CapsuleRequest,
    descs: &[Descriptor],
) -> Result<RouteDecision, RouteRefuse> {
    // A capsule-named route/transport/address is refused first, before the
    // CID is parsed: this is the strongest reason and takes precedence.
    refuse_named(req)?;
    parse_cid(&req.cid)?;
    let need = Need {
        put: req.put,
        size: req.size,
    };
    let chosen = choose(descs, need)
        .cloned()
        .ok_or_else(|| RouteRefuse::new(NO_PERMITTED_CARRIER))?;
    // The failover order starts with the chosen carrier, then every other
    // permitted get-capable carrier in descriptor order. The Runtime owns the
    // order; no extra hop is invented.
    let mut order = Vec::with_capacity(descs.len());
    order.push(chosen.name.clone());
    for d in descs {
        if d.supports_get && d.name != chosen.name {
            order.push(d.name.clone());
        }
    }
    Ok(RouteDecision { chosen, order })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(name: &str, put: bool, max: u64) -> Descriptor {
        parse_descriptor(&format!(
            "{{\"name\":\"{name}\",\"version\":\"1\",\"supports\":{{\"get\":true,\"put\":{put},\"pin\":false,\"stream\":false}},\"max_object_bytes\":{max},\"transport\":\"local\"}}"
        ))
        .expect("descriptor parses")
    }

    fn cid() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    // P15: a capsule that names its own route is refused `capsule-named-route`.
    // Falsifier: letting `route` through would let a capsule pin a Boson peer.
    #[test]
    fn capsule_named_route_is_refused() {
        let mut req = CapsuleRequest::bare(cid(), 10, false);
        req.route = Some("boson:peer-1".to_string());
        let err = decide_route(&req, &[desc("mem", false, 100)]).unwrap_err();
        assert_eq!(err.reason(), "capsule-named-route");
    }

    // P15: a capsule that names a transport is refused `capsule-named-route`.
    // Falsifier: letting `transport` through would allow a raw-socket hint.
    #[test]
    fn capsule_named_transport_is_refused() {
        let mut req = CapsuleRequest::bare(cid(), 10, false);
        req.transport = Some("tcp".to_string());
        let err = decide_route(&req, &[desc("mem", false, 100)]).unwrap_err();
        assert_eq!(err.reason(), "capsule-named-route");
    }

    // P15: a capsule that names a raw address is refused `capsule-named-route`.
    // Falsifier: letting `address` through would allow a raw-socket bypass.
    #[test]
    fn capsule_named_address_is_refused() {
        let mut req = CapsuleRequest::bare(cid(), 10, false);
        req.address = Some("127.0.0.1:4001".to_string());
        let err = decide_route(&req, &[desc("mem", false, 100)]).unwrap_err();
        assert_eq!(err.reason(), "capsule-named-route");
    }

    // P3: a fetch that nothing permitted can serve fails closed, no fallback.
    // Falsifier: any invented raw-socket/Boson carrier would make this Ok.
    #[test]
    fn nothing_fits_fails_closed() {
        let req = CapsuleRequest::bare(cid(), 500, false);
        let err = decide_route(&req, &[desc("small", false, 100)]).unwrap_err();
        assert_eq!(err.reason(), "no-permitted-carrier");
    }

    // P3: an empty permitted set fails closed with the same reason.
    // Falsifier: an empty list must not silently succeed.
    #[test]
    fn empty_permitted_set_fails_closed() {
        let req = CapsuleRequest::bare(cid(), 1, false);
        let err = decide_route(&req, &[]).unwrap_err();
        assert_eq!(err.reason(), "no-permitted-carrier");
    }

    // P3: size is respected; an undersized carrier is not chosen.
    // Falsifier: ignoring size would let the 5-byte carrier win a 100-byte need.
    #[test]
    fn size_is_respected() {
        let descs = vec![desc("alpha", false, 5), desc("beta", false, 500)];
        let decision =
            decide_route(&CapsuleRequest::bare(cid(), 100, false), &descs).expect("beta fits");
        assert_eq!(decision.chosen.name, "beta");
    }

    // P3: put support is required for a put need.
    // Falsifier: ignoring put would let a get-only carrier win a put need.
    #[test]
    fn put_need_is_enforced() {
        let req = CapsuleRequest::bare(cid(), 10, true);
        let err = decide_route(&req, &[desc("ro", false, 1000)]).unwrap_err();
        assert_eq!(err.reason(), "no-permitted-carrier");
    }

    // P3: a malformed CID is refused `bad-cid` and never reaches a store.
    // Falsifier: trusting the raw string would pass junk to a carrier.
    #[test]
    fn malformed_cid_is_refused() {
        for bad in ["nonsense", "sha256:ABCDEF", "sha256:short"] {
            let req = CapsuleRequest::bare(bad, 10, false);
            let err = decide_route(&req, &[desc("mem", false, 100)]).unwrap_err();
            assert_eq!(err.reason(), "bad-cid", "cid {:?}", bad);
        }
    }

    // P15: a bare, permitted request picks the Runtime's route in order.
    // Falsifier: choosing anything but the permitted carrier, or a wrong order.
    #[test]
    fn bare_request_picks_runtime_route_in_order() {
        let descs = vec![desc("zeta", false, 100), desc("alpha", false, 100)];
        let decision = decide_route(&CapsuleRequest::bare(cid(), 10, false), &descs)
            .expect("bare request is permitted");
        assert_eq!(decision.chosen.name, "zeta");
        assert_eq!(
            decision.order,
            vec!["zeta".to_string(), "alpha".to_string()]
        );
    }
}
