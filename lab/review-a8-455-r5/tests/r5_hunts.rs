//! New r5 false-PASS hunts against the #455 authorship lock.
//!
//! Each hunt builds a complete later-PASS receipt (session, hash, function,
//! seq) and asks whether the subject's public API still binds. SURVIVED
//! means a later cargo `ok` once the Runtime prints those fields.
//! CAUGHT means the API refuses today.

use a1_a8_hardening::{
    authorship_gaps, executed_bytes_hash, is_session_id, parse_capability_record,
    read_capability_requests_since, records_from_sealed_receipts, seal_receipt_file, sha256, Home,
    LaunchBind, ReceiptCursor, GUEST_FUNCTION_JOURNAL_GRANTS, MANIFEST_DENIED,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RESOURCE: &str = "localhost://Public/../../../../.ssh/id_ed25519";
const HASH: &str = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737";
const ASSIGNED: &str = "component-341af27a-6b9c-4892-a618-808f0b687a9d";
const SESSION: &str = "0123456789abcdef0123456789abcdef";

fn complete_line(action: &str, capsule: &str, session: &str, seq: u64) -> String {
    format!(
        r#"{{"action":"{action}","capsule_id":"{capsule}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","principal_id":null,"resource":"{RESOURCE}","seq":{seq},"session_id":"{session}"}}"#
    )
}

fn complete_records(session: &str) -> Vec<a1_a8_hardening::CapabilityRequestRecord> {
    ["write", "read"]
        .into_iter()
        .enumerate()
        .map(|(index, action)| {
            parse_capability_record(&complete_line(action, ASSIGNED, session, index as u64 + 1))
                .unwrap()
        })
        .collect()
}

fn bind(session: &str) -> LaunchBind {
    LaunchBind {
        assigned: Some(ASSIGNED.to_string()),
        session_id: Some(session.to_string()),
        guest_hash: HASH.to_string(),
    }
}

fn later_pass(session: &str) -> bool {
    authorship_gaps(&complete_records(session), &bind(session))
        .ok()
        .is_some_and(|missing| missing.is_empty())
}

fn print_verdict(id: &str, survived: bool, detail: &str) {
    let label = if survived { "SURVIVED" } else { "CAUGHT" };
    println!("{id}: {label} {detail}");
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
        .unwrap_or_else(|| "non-string panic".to_string())
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r5-{}-{}-{}",
        tag,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn h_session_from_time() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let session = format!("{nanos:032x}");
    assert_eq!(session.len(), 32);
    let accepted = is_session_id(&session) && later_pass(&session);
    print_verdict(
        "H-session-from-time",
        accepted,
        &format!("is_session_id({}) later_pass={accepted}", session),
    );
    assert!(
        accepted,
        "expected SURVIVED: 32 hex from clock binds as host-minted"
    );
}

#[test]
fn h_session_from_pid() {
    let session = format!("{:032x}", std::process::id() as u128);
    let accepted = is_session_id(&session) && later_pass(&session);
    print_verdict(
        "H-session-from-pid",
        accepted,
        &format!("is_session_id({}) later_pass={accepted}", session),
    );
    assert!(
        accepted,
        "expected SURVIVED: 32 hex from pid binds as host-minted"
    );
}

#[test]
fn h_session_all_zeros() {
    let session = "00000000000000000000000000000000";
    let accepted = is_session_id(session) && later_pass(session);
    print_verdict(
        "H-session-all-zeros",
        accepted,
        &format!("is_session_id({session}) later_pass={accepted}"),
    );
    assert!(
        accepted,
        "expected SURVIVED: 32 zero hex binds as unguessable"
    );
}

#[test]
fn h_session_reused_across_runs() {
    let first = later_pass(SESSION);
    let second = later_pass(SESSION);
    let survived = first && second;
    print_verdict(
        "H-session-reused",
        survived,
        &format!("first={first} second={second}; no used-session set"),
    );
    assert!(
        survived,
        "expected SURVIVED: the same session binds on two runs"
    );
}

#[test]
fn h_seal_is_host_held_memory() {
    let dir = temp_dir("seal-host");
    let path = dir.join("capability-requests.jsonl");
    let body = format!(
        "{}\n{}\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&path, &body).unwrap();
    let seal = seal_receipt_file(&path).unwrap();
    assert_eq!(seal.hash, sha256(body.as_bytes()));
    assert_eq!(seal.bytes, body.as_bytes());
    let sibling = path.with_extension("seal");
    assert!(
        !sibling.exists(),
        "seal must not be written next to the journal"
    );
    fs::remove_dir_all(&dir).unwrap();
    print_verdict(
        "H-seal-guest-writable",
        false,
        "seal lives in ReceiptSeal memory; no sibling file",
    );
}

#[test]
fn h_seal_before_final_append() {
    let dir = temp_dir("seal-early");
    let path = dir.join("capability-requests.jsonl");
    let first = format!("{}\n", complete_line("write", ASSIGNED, SESSION, 1));
    fs::write(&path, &first).unwrap();
    let seal = seal_receipt_file(&path).unwrap();
    let both = format!(
        "{}\n{}\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&path, both).unwrap();
    let err = records_from_sealed_receipts(&seal, &path).expect_err("grew after early seal");
    fs::remove_dir_all(&dir).unwrap();
    let caught = err.contains("rewritten after run");
    print_verdict(
        "H-seal-before-flush",
        !caught,
        &format!("early seal then append: {err}"),
    );
    assert!(caught, "early seal plus later append must FAIL");
}

#[test]
fn h_seq_overflow_wrap() {
    let mut records = complete_records(SESSION);
    records[0].seq = Some(u64::MAX);
    records[1].seq = Some(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authorship_gaps(&records, &bind(SESSION))
    }));
    match result {
        Ok(Ok(missing)) => {
            let survived = missing.is_empty();
            print_verdict(
                "H-seq-overflow-wrap",
                survived,
                &format!("MAX then 0 returned Ok({missing:?})"),
            );
            assert!(
                !survived,
                "seq wrap must not later-PASS; missing={missing:?}"
            );
        }
        Ok(Err(err)) => {
            print_verdict("H-seq-overflow-wrap", false, &format!("refused: {err}"));
        }
        Err(payload) => {
            let text = panic_text(payload);
            print_verdict(
                "H-seq-overflow-wrap",
                true,
                &format!("debug overflow panic (release wrap would bind): {text}"),
            );
            assert!(
                text.contains("overflow") || text.contains("attempt to add"),
                "expected debug overflow, got {text}"
            );
        }
    }
}

#[test]
fn h_seq_gaps() {
    let mut records = complete_records(SESSION);
    records[1].seq = Some(3);
    let err = authorship_gaps(&records, &bind(SESSION)).expect_err("1 then 3");
    let caught = err.contains("strictly increasing");
    print_verdict("H-seq-gaps", !caught, &err);
    assert!(caught, "{err}");
}

#[test]
fn h_toctou_rename_between_hash_and_load() {
    let dir = temp_dir("toctou");
    let staged = dir.join("guest.wasm");
    let honest = b"executed-bytes";
    let swapped = b"other-bytes-loaded";
    fs::write(&staged, honest).unwrap();
    let hashed = executed_bytes_hash(&fs::read(&staged).unwrap(), honest).unwrap();
    let backup = dir.join("guest.wasm.honest");
    fs::rename(&staged, &backup).unwrap();
    fs::write(&staged, swapped).unwrap();
    let loaded = fs::read(&staged).unwrap();
    fs::remove_file(&staged).unwrap();
    fs::rename(&backup, &staged).unwrap();
    let after = executed_bytes_hash(&fs::read(&staged).unwrap(), honest).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let survived = hashed == after && hashed == sha256(honest) && loaded == swapped;
    print_verdict(
        "H-toctou-rename",
        survived,
        "hash, rename-swap, load, rename-back: both hashes match honest; load saw swap",
    );
    assert!(
        survived,
        "expected SURVIVED: executed_bytes_hash does not lock the staged inode at load"
    );
}

#[test]
fn h_mmap_swap() {
    let dir = temp_dir("mmap");
    let path = dir.join("guest.wasm");
    fs::write(&path, b"executed-bytes").unwrap();
    let claimed = fs::read(&path).unwrap();
    let hashed = executed_bytes_hash(&claimed, &claimed).unwrap();
    fs::write(&path, b"other-bytes-loaded").unwrap();
    let after_read = fs::read(&path).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let survived = hashed == sha256(b"other-bytes-loaded");
    print_verdict(
        "H-mmap-swap",
        survived,
        &format!(
            "hash is of a Vec snapshot ({hashed}); later file bytes sha256 {}",
            sha256(&after_read)
        ),
    );
    assert!(
        !survived,
        "expected CAUGHT: hash is a copy, not a live mmap"
    );
}

#[test]
fn h_unicode_lookalike_keys() {
    // Cyrillic 'с' (U+0441) in the key. The real capsule_id field is absent.
    let line = format!(
        r#"{{"action":"write","сapsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":1,"session_id":"{SESSION}"}}"#
    );
    let parsed = parse_capability_record(&line);
    let later = match &parsed {
        Ok(record) => authorship_gaps(std::slice::from_ref(record), &bind(SESSION))
            .ok()
            .is_some_and(|missing| missing.is_empty()),
        Err(_) => false,
    };
    print_verdict(
        "H-unicode-lookalike-keys",
        later,
        &format!("parse={parsed:?} later_pass={later}"),
    );
    assert!(!later, "lookalike key must not later-PASS");
}

#[test]
fn h_nan_and_large_numbers() {
    let cases = [
        (
            "nan",
            format!(
                r#"{{"action":"write","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":NaN,"session_id":"{SESSION}"}}"#
            ),
        ),
        (
            "u64-plus",
            format!(
                r#"{{"action":"write","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":18446744073709551616,"session_id":"{SESSION}"}}"#
            ),
        ),
        (
            "neg",
            format!(
                r#"{{"action":"write","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":-1,"session_id":"{SESSION}"}}"#
            ),
        ),
        (
            "float",
            format!(
                r#"{{"action":"write","capsule_id":"{ASSIGNED}","code":"{MANIFEST_DENIED}","guest_function":"{GUEST_FUNCTION_JOURNAL_GRANTS}","module_hash":"{HASH}","resource":"{RESOURCE}","seq":1.5,"session_id":"{SESSION}"}}"#
            ),
        ),
    ];
    let mut any_pass = false;
    for (name, line) in cases {
        let parsed = parse_capability_record(&line);
        let later = match &parsed {
            Ok(record) => authorship_gaps(std::slice::from_ref(record), &bind(SESSION))
                .ok()
                .is_some_and(|missing| missing.is_empty()),
            Err(_) => false,
        };
        println!("H-nan-large:{name} parse={parsed:?} later_pass={later}");
        any_pass |= later;
    }
    print_verdict("H-nan-large-numbers", any_pass, "NaN/u64+/neg/1.5");
    assert!(!any_pass, "NaN or large seq must not later-PASS");
}

#[test]
fn h_bom_jsonl() {
    let dir = temp_dir("bom");
    let path = dir.join("capability-requests.jsonl");
    let body = format!(
        "\u{feff}{}\n{}\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&path, body.as_bytes()).unwrap();
    let cursor = ReceiptCursor {
        path: path.clone(),
        inode: Some(fs::metadata(&path).unwrap().ino()),
        size: fs::metadata(&path).unwrap().len(),
        offset: 0,
    };
    let records = read_capability_requests_since(&cursor).unwrap();
    let later = authorship_gaps(&records, &bind(SESSION))
        .ok()
        .is_some_and(|missing| missing.is_empty());
    fs::remove_dir_all(&dir).unwrap();
    print_verdict(
        "H-bom",
        later,
        &format!(
            "BOM dropped the first line; remaining complete line later_pass={later} records={}",
            records.len()
        ),
    );
    assert!(
        later && records.len() == 1,
        "expected SURVIVED: BOM drops write; the remaining complete read later-PASSes authorship"
    );
}

#[test]
fn h_crlf_jsonl() {
    let dir = temp_dir("crlf");
    let path = dir.join("capability-requests.jsonl");
    let body = format!(
        "{}\r\n{}\r\n",
        complete_line("write", ASSIGNED, SESSION, 1),
        complete_line("read", ASSIGNED, SESSION, 2)
    );
    fs::write(&path, body.as_bytes()).unwrap();
    let cursor = ReceiptCursor {
        path: path.clone(),
        inode: Some(fs::metadata(&path).unwrap().ino()),
        size: fs::metadata(&path).unwrap().len(),
        offset: 0,
    };
    let records = read_capability_requests_since(&cursor).unwrap();
    let later = authorship_gaps(&records, &bind(SESSION))
        .ok()
        .is_some_and(|missing| missing.is_empty());
    fs::remove_dir_all(&dir).unwrap();
    print_verdict(
        "H-crlf",
        false,
        &format!(
            "HONEST records={} later_pass={later}; CRLF is valid JSONL, not a false PASS",
            records.len()
        ),
    );
    assert!(later && records.len() == 2, "CRLF jsonl must still parse");
}

#[test]
fn h_truncated_final_line() {
    let dir = temp_dir("trunc");
    let path = dir.join("capability-requests.jsonl");
    let write = complete_line("write", ASSIGNED, SESSION, 1);
    let read = complete_line("read", ASSIGNED, SESSION, 2);
    let body = format!("{write}\n{read}");
    fs::write(&path, body.as_bytes()).unwrap();
    let cursor = ReceiptCursor {
        path: path.clone(),
        inode: Some(fs::metadata(&path).unwrap().ino()),
        size: fs::metadata(&path).unwrap().len(),
        offset: 0,
    };
    let records = read_capability_requests_since(&cursor).unwrap();
    let later = authorship_gaps(&records, &bind(SESSION))
        .ok()
        .is_some_and(|missing| missing.is_empty());
    fs::remove_dir_all(&dir).unwrap();
    print_verdict(
        "H-truncated-final-line",
        later,
        &format!(
            "truncated read dropped; remaining complete write later_pass={later} records={}",
            records.len()
        ),
    );
    assert!(
        later && records.len() == 1,
        "expected SURVIVED: one remaining complete line later-PASSes authorship"
    );
}

#[test]
fn h_symlinked_journal() {
    let home = Home::new();
    let path = home.receipts_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = home.home().join("guest-writable.jsonl");
    symlink(&target, &path).unwrap();
    let absent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        home.assert_receipts_absent();
    }));
    let dangling_ok = absent.is_ok();
    if dangling_ok {
        fs::write(
            &target,
            format!(
                "{}\n{}\n",
                complete_line("write", ASSIGNED, SESSION, 1),
                complete_line("read", ASSIGNED, SESSION, 2)
            ),
        )
        .unwrap();
        home.lock_launch_receipts();
        let records = home.receipts_since_launch();
        let later = authorship_gaps(&records, &bind(SESSION))
            .ok()
            .is_some_and(|missing| missing.is_empty());
        print_verdict(
            "H-symlink-journal",
            later || dangling_ok,
            &format!(
                "dangling symlink treated as absent; records={} later_pass={later}",
                records.len()
            ),
        );
        home.finish();
        assert!(
            dangling_ok,
            "expected SURVIVED: exists() misses a dangling symlink"
        );
    } else {
        print_verdict(
            "H-symlink-journal",
            false,
            &panic_text(absent.err().unwrap()),
        );
        home.finish();
    }
}

#[test]
fn h_hardlinked_journal() {
    let home = Home::new();
    let path = home.receipts_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let other = home.home().join("other.jsonl");
    fs::write(
        &other,
        format!(
            "{}\n{}\n",
            complete_line("write", ASSIGNED, SESSION, 1),
            complete_line("read", ASSIGNED, SESSION, 2)
        ),
    )
    .unwrap();
    fs::hard_link(&other, &path).unwrap();
    let absent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        home.assert_receipts_absent();
    }));
    let survived = absent.is_ok();
    print_verdict(
        "H-hardlink-journal",
        survived,
        if survived {
            "hardlink of a pre-written file treated as absent"
        } else {
            "exists() sees the hardlink; pre-exist CAUGHT"
        },
    );
    home.finish();
    assert!(!survived, "hardlinked pre-written journal must be refused");
}

#[test]
fn h_tmpfs_remount() {
    let dir = temp_dir("tmpfs");
    let path = dir.join("capability-requests.jsonl");
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            complete_line("write", ASSIGNED, SESSION, 1),
            complete_line("read", ASSIGNED, SESSION, 2)
        ),
    )
    .unwrap();
    let before = fs::metadata(&path).unwrap().ino();
    let mount = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "remount", dir.to_str().unwrap()])
        .output()
        .expect("start mount");
    let ok = mount.status.success();
    let after = fs::metadata(&path).ok().map(|meta| meta.ino());
    println!(
        "H-tmpfs-remount: NOT RUN mount_ok={ok} inode_before={before} inode_after={after:?} stderr={}",
        String::from_utf8_lossy(&mount.stderr).trim()
    );
    let _ = fs::remove_dir_all(&dir);
    assert!(!ok, "tmpfs remount is NOT RUN without CAP_SYS_ADMIN");
}
