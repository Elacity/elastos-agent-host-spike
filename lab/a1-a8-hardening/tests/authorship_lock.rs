//! Closed authorship lock for the day the Runtime prints a session id.
//! Judge only from host-side receipts. Each survivor from review r4 has
//! one test here.

use a1_a8_hardening::{
    assigned_session_id, authorship_gaps, executed_bytes_hash, executed_bytes_still_sealed,
    is_session_id, mint_session_id, parse_capability_record, read_capability_requests_since,
    records_from_sealed_receipts, seal_receipt_file, seal_staged_bytes, sha256, Home, LaunchBind,
    ReceiptCursor, GUEST_FUNCTION_JOURNAL_GRANTS, MANIFEST_DENIED,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};

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

#[test]
fn session_from_time_is_refused() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let session = format!("{nanos:032x}");
    assert_eq!(session.len(), 32);
    assert!(
        !is_session_id(&session),
        "session_id must be an unguessable per-launch id"
    );
    let records = complete_records(&session);
    let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(&session)))
        .expect_err("session_id must be an unguessable per-launch id");
    assert!(
        err.contains("session_id must be an unguessable per-launch id"),
        "{err}"
    );
    assert!(assigned_session_id(&format!("[run] session_id={session}")).is_none());
}

#[test]
fn session_from_pid_is_refused() {
    let session = format!("{:032x}", std::process::id() as u128);
    assert!(
        !is_session_id(&session),
        "session_id must be an unguessable per-launch id"
    );
    let records = complete_records(&session);
    let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(&session)))
        .expect_err("session_id must be an unguessable per-launch id");
    assert!(
        err.contains("session_id must be an unguessable per-launch id"),
        "{err}"
    );
}

#[test]
fn session_all_zeros_is_refused() {
    let session = "00000000000000000000000000000000";
    assert!(
        !is_session_id(session),
        "session_id must be an unguessable per-launch id"
    );
    let records = complete_records(session);
    let err = authorship_gaps(&records, &bind(Some(ASSIGNED), Some(session)))
        .expect_err("session_id must be an unguessable per-launch id");
    assert!(
        err.contains("session_id must be an unguessable per-launch id"),
        "{err}"
    );
    let minted = mint_session_id();
    assert!(
        is_session_id(&minted),
        "session_id must be an unguessable per-launch id"
    );
    assert_ne!(minted, session);
}

#[test]
fn session_reused_across_runs_is_refused() {
    let home = Home::new();
    let minted = mint_session_id();
    home.record_session(&minted)
        .expect("first host-minted session is recorded");
    let err = home
        .record_session(&minted)
        .expect_err("session_id reused across runs");
    home.finish();
    assert!(
        err.contains("session_id reused across runs"),
        "session_id reused across runs; {err}"
    );
}

#[test]
fn receipt_seq_wrap_is_refused() {
    let mut records = complete_records(SESSION);
    records[0].seq = Some(u64::MAX);
    records[1].seq = Some(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authorship_gaps(&records, &bind(Some(ASSIGNED), Some(SESSION)))
    }));
    let err = match result {
        Ok(Err(err)) => err,
        Ok(Ok(missing)) => panic!(
            "receipt seq must be strictly increasing without gaps or repeats; wrap at u64::MAX is refused; missing={missing:?}"
        ),
        Err(payload) => panic!(
            "receipt seq must be strictly increasing without gaps or repeats; wrap at u64::MAX is refused; {}",
            panic_text(payload)
        ),
    };
    assert!(
        err.contains("receipt seq must be strictly increasing without gaps or repeats"),
        "{err}"
    );
    assert!(err.contains("wrap at u64::MAX is refused"), "{err}");
}

#[test]
fn staged_rename_between_hash_and_load_fails() {
    let dir = std::env::temp_dir().join(format!(
        "a8-toctou-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let staged = dir.join("guest.wasm");
    let honest = b"executed-bytes";
    let swapped = b"other-bytes-loaded";
    fs::write(&staged, honest).unwrap();
    let seal = seal_staged_bytes(&staged).unwrap();
    assert_eq!(seal.hash, sha256(honest));
    let backup = dir.join("guest.wasm.honest");
    fs::rename(&staged, &backup).unwrap();
    fs::write(&staged, swapped).unwrap();
    let err = executed_bytes_still_sealed(&seal)
        .expect_err("module_hash must be of the exact bytes executed");
    let _ = fs::remove_dir_all(&dir);
    assert!(
        err.contains("module_hash must be of the exact bytes executed"),
        "{err}"
    );
}

#[test]
fn dangling_symlink_journal_is_refused() {
    let home = Home::new();
    let path = home.receipts_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = home.home().join("guest-writable.jsonl");
    symlink(&target, &path).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        home.assert_receipts_absent();
    }));
    let err = match result {
        Err(payload) => panic_text(payload),
        Ok(()) => {
            home.finish();
            panic!(
                "capability-requests.jsonl must not exist before the guest is launched ({})",
                path.display()
            );
        }
    };
    home.finish();
    assert!(
        err.contains("capability-requests.jsonl must not exist before the guest is launched"),
        "{err}"
    );
}

#[test]
fn bom_or_truncated_journal_is_refused() {
    let dir = std::env::temp_dir().join(format!(
        "a8-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let bom_path = dir.join("bom.jsonl");
    let bom_body = format!(
        "\u{feff}{}\n{}\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&bom_path, bom_body.as_bytes()).unwrap();
    let bom_cursor = ReceiptCursor {
        path: bom_path.clone(),
        inode: Some(fs::metadata(&bom_path).unwrap().ino()),
        size: fs::metadata(&bom_path).unwrap().len(),
        offset: 0,
    };
    match read_capability_requests_since(&bom_cursor) {
        Err(Some(reason)) => assert!(
            reason.contains("capability-requests.jsonl must not start with a BOM"),
            "{reason}"
        ),
        other => panic!("capability-requests.jsonl must not start with a BOM; got {other:?}"),
    }

    let trunc_path = dir.join("trunc.jsonl");
    let write = complete_line("write", ASSIGNED, SESSION, 1);
    let read = complete_line("read", ASSIGNED, SESSION, 2);
    fs::write(&trunc_path, format!("{write}\n{read}")).unwrap();
    let trunc_cursor = ReceiptCursor {
        path: trunc_path.clone(),
        inode: Some(fs::metadata(&trunc_path).unwrap().ino()),
        size: fs::metadata(&trunc_path).unwrap().len(),
        offset: 0,
    };
    let live = read_capability_requests_since(&trunc_cursor).unwrap();
    let later = authorship_gaps(&live, &bind(Some(ASSIGNED), Some(SESSION)))
        .ok()
        .is_some_and(|missing| missing.is_empty());
    assert!(
        !later,
        "capability-requests.jsonl truncated final line; one complete line must not bind"
    );
    assert!(
        live.len() != 2
            || authorship_gaps(&live, &bind(Some(ASSIGNED), Some(SESSION)))
                .unwrap()
                .contains(&"write-then-read pair"),
        "capability-requests.jsonl truncated final line"
    );
    fs::write(&trunc_path, format!("{write}\n{read}")).unwrap();
    let seal = seal_receipt_file(&trunc_path).unwrap();
    let err = records_from_sealed_receipts(&seal, &trunc_path)
        .expect_err("capability-requests.jsonl truncated final line");
    let _ = fs::remove_dir_all(&dir);
    assert!(
        err.contains("capability-requests.jsonl truncated final line"),
        "{err}"
    );
}
