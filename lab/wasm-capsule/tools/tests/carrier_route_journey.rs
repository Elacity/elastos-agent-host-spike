// Built-by: deepseek-v4.1-flash-1017-ultrafast
//! P2-9 journey (integration): the Runtime stand-in refuses a capsule-named
//! route/transport/address (`capsule-named-route`), respects size and put,
//! and fails closed `no-permitted-carrier` with no raw-socket or Boson
//! fallback. Each test names its P# and its falsifier.

use wasm_capsule_tools::carrier_route::{
    decide_route, parse_descriptor, CapsuleRequest, Descriptor,
};

fn desc(name: &str, put: bool, max: u64) -> Descriptor {
    parse_descriptor(&format!(
        "{{\"name\":\"{name}\",\"version\":\"1\",\"supports\":{{\"get\":true,\"put\":{put},\"pin\":false,\"stream\":false}},\"max_object_bytes\":{max},\"transport\":\"local\"}}"
    ))
    .expect("descriptor parses")
}

fn cid() -> String {
    format!("sha256:{}", "a".repeat(64))
}

// P15: no capsule-named shortcut is honored, all three refused identically.
// Falsifier: any of these returning Ok would allow a raw/Boson bypass.
#[test]
fn journey_all_shortcuts_refused() {
    let descs = vec![desc("mem", false, 1000)];
    let mut reqs = Vec::new();
    let mut r = CapsuleRequest::bare(cid(), 10, false);
    r.route = Some("boson:peer".into());
    reqs.push(r);
    let mut r = CapsuleRequest::bare(cid(), 10, false);
    r.transport = Some("http".into());
    reqs.push(r);
    let mut r = CapsuleRequest::bare(cid(), 10, false);
    r.address = Some("10.0.0.1:8080".into());
    reqs.push(r);
    for req in &reqs {
        let err = decide_route(req, &descs).expect_err("shortcut refused");
        assert_eq!(err.reason(), "capsule-named-route");
    }
}

// P3: an oversize need fails closed, never a fallback carrier.
// Falsifier: a fallback would make this Ok instead of `no-permitted-carrier`.
#[test]
fn journey_oversize_fails_closed() {
    let descs = vec![desc("mem", false, 1000)];
    let req = CapsuleRequest::bare(cid(), 10_000, false);
    let err = decide_route(&req, &descs).expect_err("oversize fails closed");
    assert_eq!(err.reason(), "no-permitted-carrier");
}

// P3/P15: a bare permitted request routes to the fitting put-capable carrier.
// Falsifier: choosing a non-fitting or get-only carrier breaks the assert.
#[test]
fn journey_bare_request_routes_correctly() {
    let descs = vec![
        desc("tiny", false, 5),
        desc("big-get", false, 5000),
        desc("big-put", true, 5000),
    ];
    let req = CapsuleRequest::bare(cid(), 100, true);
    let decision = decide_route(&req, &descs).expect("a put-capable carrier fits");
    assert_eq!(decision.chosen.name, "big-put");
    assert_eq!(decision.order.first().map(String::as_str), Some("big-put"));
}
