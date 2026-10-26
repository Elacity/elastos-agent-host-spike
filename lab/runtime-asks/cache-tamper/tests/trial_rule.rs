//! The trial rule, not the Runtime. A plant that sets `TRUST_RACY_STAMP`
//! makes `trial_rule_refuses_a_racy_same_size_rewrite` fail.

use cache_tamper::{same_generation, stamp_is_racy};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{FileExt, MetadataExt};

fn coarse_now() -> (i64, i64) {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut now) },
        0
    );
    (now.tv_sec, now.tv_nsec)
}

fn wait_for_fresh_tick() {
    let start = coarse_now();
    while coarse_now() == start {
        std::hint::spin_loop();
    }
}

fn sha(path: &std::path::Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

#[test]
fn trial_rule_refuses_a_racy_same_size_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact");
    wait_for_fresh_tick();
    fs::write(&path, b"working-image").unwrap();
    let before = fs::symlink_metadata(&path).unwrap();
    let before_sha = sha(&path);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .write_all_at(b"changed-image", 0)
        .unwrap();
    let mtime = before.modified().unwrap();
    fs::File::open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(mtime))
        .unwrap();
    let after = fs::symlink_metadata(&path).unwrap();
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        // This attempt crossed a tick. The Runtime stamp path would already
        // refuse. The rule is about the case the stamp path misses.
        return;
    }
    let after_sha = sha(&path);
    assert_ne!(before_sha, after_sha);
    let racy = stamp_is_racy(
        (after.ctime(), after.ctime_nsec()),
        coarse_now(),
    );
    assert!(
        !same_generation(true, racy, before_sha == after_sha),
        "a racy same-size rewrite must not be a cache generation"
    );
}

#[test]
fn trial_rule_trusts_an_old_matching_stamp() {
    assert!(same_generation(true, false, false));
    assert!(same_generation(true, false, true));
    assert!(!same_generation(false, false, true));
}
