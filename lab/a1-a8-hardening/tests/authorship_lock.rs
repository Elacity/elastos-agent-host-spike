//! Closed authorship lock for the day the Runtime prints a session id.
//! Judge only from host-side receipts. Each survivor from review r4 has
//! one test here.

use a1_a8_hardening::{
    assigned_session_id, authorship_gaps, executed_bytes_hash, is_session_id,
    parse_capability_record, records_from_sealed_receipts, seal_receipt_file, sha256, Home,
    LaunchBind, GUEST_FUNCTION_JOURNAL_GRANTS, MANIFEST_DENIED,
};
use std::fs;

const RESOURCE: &str = "localhost://Public/../../../../.ssh/id_ed25519";
const HASH: &str = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737";
const ASSIGNED: &str = "component-341af27a-6b9c-4892-a618-808f0b687a9d";
const SESSION: &str = "0123456789abcdef0123456789abcdef";

fn denied(action: &str, capsule: &str) -> String {
    format!(
        r#"{{"action":"{action}","capsule_id":"{capsule}","code":"{MANIFEST_DENIED}","principal_id":null,"resource":"{RESOURCE}"}}"#
    )
}

fn complete_line(action: &str, capsule: &str, session: &str, seq: u64) -> String {
    format!(
        r#"{{"action":"{action}","capsule_id":"{capsule}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","principal_id":null,"resource":"{RESOURCE}","seq":{seq},"session_id":"{session}"}}"#
    )
}

fn complete_records(session: &str) -> Vec<a1_a8_hardening::CapabilityRequestRecord> {
    complete_records_on(ASSIGNED, session)
}

fn complete_records_on(
    capsule: &str,
    session: &str,
) -> Vec<a1_a8_hardening::CapabilityRequestRecord> {
    ["write", "read"]
        .into_iter()
        .enumerate()
        .map(|(index, action)| {
            parse_capability_record(&complete_line(action, capsule, session, index as u64 + 1))
                .unwrap()
        })
        .collect()
}

fn bind(assigned: Option<&str>, session: Option<&str>) -> LaunchBind {
    LaunchBind {
        assigned: assigned.map(str::to_string),
        session_id: session.map(str::to_string),
        guest_hash: HASH.to_string(),
    }
}

#[test]
fn session_id_must_not_alias_capsule_id() {
    const IDENTITY_SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let records = complete_records_on(IDENTITY_SESSION, IDENTITY_SESSION);
    let err = authorship_gaps(&records, &bind(Some(IDENTITY_SESSION), Some(SESSION)))
        .expect_err("session_id must not alias capsule_id or identity::context().session");
    assert!(
        err.contains("session_id must not alias capsule_id or identity::context().session"),
        "session_id must not alias capsule_id or identity::context().session; {err}"
    );
    assert!(assigned_session_id(&format!("[run] session_id={ASSIGNED}")).is_none());
}

#[test]
fn predictable_session_1_is_refused() {
    assert!(
        !is_session_id("session-1"),
        "session_id must be an unguessable per-launch id"
    );
    assert!(
        !is_session_id("session-this-launch"),
        "session_id must be an unguessable per-launch id"
    );
    assert!(is_session_id(SESSION));
    assert!(is_session_id(&format!("session-{SESSION}")));
    assert!(assigned_session_id("[run] session_id=session-1").is_none());
    let records = complete_records("session-1");
    let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some("session-1")))
        .expect_err("session_id must be an unguessable per-launch id");
    assert!(
        err.contains("session_id must be an unguessable per-launch id"),
        "{err}"
    );
}

#[test]
fn executed_hash_is_of_staged_bytes() {
    let staged = b"executed-bytes";
    let claimed = b"other-bytes";
    let err = executed_bytes_hash(staged, claimed)
        .expect_err("module_hash must be of the exact bytes executed");
    assert!(
        err.contains("module_hash must be of the exact bytes executed"),
        "{err}"
    );
    assert_eq!(executed_bytes_hash(staged, staged).unwrap(), sha256(staged));
}

#[test]
fn receipt_seq_must_be_strictly_increasing() {
    let mut gap = complete_records(SESSION);
    gap[1].seq = Some(3);
    let err = authorship_gaps(&gap, &bind(Some(ASSIGNED), Some(SESSION)))
        .expect_err("receipt seq must be strictly increasing without gaps or repeats");
    assert!(
        err.contains("receipt seq must be strictly increasing without gaps or repeats"),
        "{err}"
    );
    let mut repeat = complete_records(SESSION);
    repeat[1].seq = Some(1);
    let err = authorship_gaps(&repeat, &bind(Some(ASSIGNED), Some(SESSION)))
        .expect_err("receipt seq must be strictly increasing without gaps or repeats");
    assert!(
        err.contains("receipt seq must be strictly increasing without gaps or repeats"),
        "{err}"
    );
    let mut reorder = complete_records(SESSION);
    reorder[0].seq = Some(2);
    reorder[1].seq = Some(1);
    let err = authorship_gaps(&reorder, &bind(Some(ASSIGNED), Some(SESSION)))
        .expect_err("receipt seq must be strictly increasing without gaps or repeats");
    assert!(
        err.contains("receipt seq must be strictly increasing without gaps or repeats"),
        "{err}"
    );
}

#[test]
fn same_inode_shrink_fails() {
    let home = Home::new();
    let path = home.receipts_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = format!(
        "{}\n{}\n",
        denied("write", ASSIGNED),
        denied("read", ASSIGNED)
    );
    fs::write(&path, &body).unwrap();
    home.lock_launch_receipts();
    fs::write(&path, &body[..body.len() / 2]).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        home.receipts_since_launch()
    }));
    home.finish();
    let err = panic_text(result.err().expect("shrank after launch"));
    assert!(err.contains("shrank after launch"), "{err}");
}

#[test]
fn rewrite_after_seal_fails() {
    let dir = std::env::temp_dir().join(format!(
        "a8-rewrite-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("capability-requests.jsonl");
    let honest = format!(
        "{}\n{}\n",
        denied("write", ASSIGNED),
        denied("read", ASSIGNED)
    );
    fs::write(&path, &honest).unwrap();
    let seal = seal_receipt_file(&path).unwrap();
    let forged = format!(
        "{}\n{}\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&path, forged).unwrap();
    let err = records_from_sealed_receipts(&seal, &path).expect_err("rewritten after run");
    fs::remove_dir_all(&dir).unwrap();
    assert!(err.contains("rewritten after run"), "{err}");
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
        })
        .unwrap_or_default()
}

#[test]
fn duplicate_json_keys_fail() {
    let line = format!(
        r#"{{"action":"write","capsule_id":"component-00000000-0000-0000-0000-000000000000","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","resource":"{RESOURCE}"}}"#
    );
    let err = parse_capability_record(&line).expect_err("duplicate JSON key capsule_id");
    assert!(err.contains("duplicate JSON key capsule_id"), "{err}");
}

#[test]
fn capsule_id_whitespace_fails() {
    let line = format!(
        r#"{{"action":"write","capsule_id":"  {ASSIGNED}  ","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":1,"session_id":"{SESSION}"}}"#
    );
    let record = parse_capability_record(&line).unwrap();
    let err = authorship_gaps(&[record], &bind(Some(ASSIGNED), Some(SESSION)))
        .expect_err("capsule_id must be byte-exact; whitespace is refused");
    assert!(
        err.contains("capsule_id must be byte-exact; whitespace is refused"),
        "capsule_id must be byte-exact; whitespace is refused; {err}"
    );
}
