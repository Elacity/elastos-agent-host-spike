//! r3 hunts, compiled only inside the #343 worktree for one run.
//! Not part of draft PR #343. Restored after the review compile.

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::a12;
use crate::a6;

fn hunt(id: &str, verdict: &str, detail: &str) {
    println!("HUNT {id}: {verdict} | {detail}");
}

fn isolated_watch(label: &str) -> PathBuf {
    a12::isolated_dir(label)
}

#[test]
fn r3_child_process_leftover_under_watch() {
    let parent = isolated_watch("r3-child");
    let before = a12::snapshot(&parent).expect("before");
    let leftover = parent.join("from-child.txt");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("printf 'child-leftover\\n' > '{}'", leftover.display()))
        .status()
        .expect("child write");
    assert!(status.success(), "child write failed: {status}");
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|path| path.ends_with("from-child.txt"));
    a12::remove_isolated(&parent);
    hunt(
        "child-process",
        if found { "CAUGHT" } else { "SURVIVED" },
        &format!("leftovers={leftovers:?}"),
    );
}

#[test]
fn r3_leftover_after_census_call() {
    let parent = isolated_watch("r3-after-census");
    let before = a12::snapshot(&parent).expect("before");
    let at_census = a12::leftovers_created(&before, &parent).expect("first census");
    fs::write(parent.join("late.txt"), b"after the census call\n").unwrap();
    let after_late = a12::leftovers_created(&before, &parent).expect("second census");
    let late_in_first = at_census.iter().any(|path| path.ends_with("late.txt"));
    let late_in_second = after_late.iter().any(|path| path.ends_with("late.txt"));
    a12::remove_isolated(&parent);
    hunt(
        "after-census-first-call",
        if late_in_first {
            "CAUGHT"
        } else {
            "SURVIVED"
        },
        "a leftover written after leftovers_created returns is absent from that result",
    );
    hunt(
        "after-census-rescan",
        if late_in_second { "CAUGHT" } else { "SURVIVED" },
        "re-running leftovers_created with the same before snapshot",
    );
}

#[test]
fn r3_sibling_outside_watch_is_invisible() {
    let watch = isolated_watch("r3-watch");
    let before = a12::snapshot(&watch).expect("before");
    let pid = std::process::id();
    let tmpdir = std::env::temp_dir().join(format!("r3-sibling-tmpdir-{pid}"));
    let xdg = std::env::temp_dir().join(format!("r3-sibling-xdg-{pid}"));
    let caches = std::env::temp_dir().join(format!("r3-sibling-caches-{pid}"));
    fs::create_dir_all(&tmpdir).unwrap();
    fs::create_dir_all(&xdg).unwrap();
    fs::create_dir_all(caches.join("Library/Caches")).unwrap();
    fs::write(tmpdir.join("outside.txt"), b"tmpdir leftover\n").unwrap();
    fs::write(xdg.join("outside.txt"), b"xdg leftover\n").unwrap();
    fs::write(
        caches.join("Library/Caches").join("outside.txt"),
        b"caches leftover\n",
    )
    .unwrap();
    let leftovers = a12::leftovers_created(&before, &watch).expect("created-set");
    let saw_outside = leftovers.iter().any(|path| path.ends_with("outside.txt"));
    let _ = fs::remove_dir_all(&tmpdir);
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::remove_dir_all(&caches);
    a12::remove_isolated(&watch);
    hunt(
        "sibling-outside-watch",
        if saw_outside { "CAUGHT" } else { "SURVIVED" },
        &format!(
            "watch leftovers={leftovers:?}; planted in TMPDIR, fake XDG, fake Library/Caches"
        ),
    );
}

#[test]
fn r3_hardlink_new_path_after_snapshot() {
    let parent = isolated_watch("r3-hard-after");
    let before = a12::snapshot(&parent).expect("before");
    let orig = parent.join("orig.txt");
    fs::write(&orig, b"hardlink-body\n").unwrap();
    let link = parent.join("link.txt");
    fs::hard_link(&orig, &link).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let saw_orig = leftovers.iter().any(|path| path.ends_with("orig.txt"));
    let saw_link = leftovers.iter().any(|path| path.ends_with("link.txt"));
    a12::remove_isolated(&parent);
    hunt(
        "hardlink-created-after",
        if saw_orig && saw_link {
            "CAUGHT"
        } else {
            "SURVIVED"
        },
        &format!("saw_orig={saw_orig} saw_link={saw_link} leftovers={leftovers:?}"),
    );
}

#[test]
fn r3_hardlink_of_preexisting_file() {
    let parent = isolated_watch("r3-hard-pre");
    let orig = parent.join("orig.txt");
    fs::write(&orig, b"already-there\n").unwrap();
    let before = a12::snapshot(&parent).expect("before");
    let link = parent.join("link.txt");
    fs::hard_link(&orig, &link).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let saw_link = leftovers.iter().any(|path| path.ends_with("link.txt"));
    a12::remove_isolated(&parent);
    hunt(
        "hardlink-preexisting",
        if saw_link { "CAUGHT" } else { "SURVIVED" },
        &format!("same inode, new path after snapshot; leftovers={leftovers:?}"),
    );
}

#[test]
fn r3_inode_reuse_same_path() {
    let parent = isolated_watch("r3-reuse");
    let path = parent.join("slot.txt");
    fs::write(&path, b"first\n").unwrap();
    let before_ino = fs::symlink_metadata(&path).unwrap().ino();
    let before = a12::snapshot(&parent).expect("before");
    fs::remove_file(&path).unwrap();
    let mut reused = false;
    let mut last_ino = 0;
    for i in 0..300 {
        fs::write(&path, format!("second-{i}\n")).unwrap();
        last_ino = fs::symlink_metadata(&path).unwrap().ino();
        if last_ino == before_ino {
            reused = true;
            break;
        }
        fs::remove_file(&path).unwrap();
    }
    if !path.exists() {
        fs::write(&path, b"second-final\n").unwrap();
        last_ino = fs::symlink_metadata(&path).unwrap().ino();
    }
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    let verdict = if !reused {
        "INCONCLUSIVE"
    } else if found {
        "CAUGHT"
    } else {
        "SURVIVED"
    };
    hunt(
        "inode-reuse-same-path",
        verdict,
        &format!("reused={reused} before_ino={before_ino} last_ino={last_ino} found={found}"),
    );
}

#[test]
fn r3_snapshot_after_runtime_already_wrote() {
    let parent = isolated_watch("r3-late-snap");
    let leftover =
        a12::create_plain_leftover(&parent, "already.txt", b"runtime wrote first\n").expect("write");
    let before = a12::snapshot(&parent).expect("snapshot after write");
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|path| path == &leftover);
    a12::remove_isolated(&parent);
    hunt(
        "snapshot-after-write",
        if found { "CAUGHT" } else { "SURVIVED" },
        "created-set hides leftovers that were already present when snapshot() ran",
    );
}

#[test]
fn r3_guard_dotdot() {
    let iso = a12::isolation_root();
    let escaped = iso.join("..");
    match a12::check_tmp_root(&escaped) {
        Ok(()) => hunt(
            "guard-dotdot",
            "SURVIVED",
            &format!("accepted {} (lexical child of isolation, filesystem parent)", escaped.display()),
        ),
        Err(reason) => hunt("guard-dotdot", "CAUGHT", &reason),
    }
    let nested = iso.join("hold").join("..").join("..");
    match a12::check_tmp_root(&nested) {
        Ok(()) => hunt(
            "guard-dotdot-nested",
            "SURVIVED",
            &format!("accepted {}", nested.display()),
        ),
        Err(reason) => hunt("guard-dotdot-nested", "CAUGHT", &reason),
    }
}

#[test]
fn r3_guard_trailing_slash() {
    let iso = a12::isolation_root();
    let with_slash = PathBuf::from(format!("{}/", iso.display()));
    match a12::check_tmp_root(&with_slash) {
        Ok(()) => hunt(
            "guard-trailing-slash",
            "CAUGHT",
            "trailing slash under isolation is accepted as the isolated folder",
        ),
        Err(reason) => hunt("guard-trailing-slash", "SURVIVED", &reason),
    }
    for (id, raw) in [
        ("guard-slash-dot", "/."),
        ("guard-slash-slash", "//"),
        ("guard-slash-dotdot", "/.."),
    ] {
        match a12::check_tmp_root(Path::new(raw)) {
            Ok(()) => hunt(id, "SURVIVED", &format!("accepted {raw}")),
            Err(reason) => hunt(id, "CAUGHT", &reason),
        }
    }
}

#[test]
fn r3_guard_relative() {
    match a12::check_tmp_root(Path::new("relative-tmp")) {
        Ok(()) => hunt("guard-relative", "SURVIVED", "relative path accepted"),
        Err(reason) => hunt("guard-relative", "CAUGHT", &reason),
    }
}

#[test]
fn r3_guard_symlinked_mktemp_and_live_home() {
    let iso = a12::isolation_root();
    let pid = std::process::id();
    let fake_live = std::env::temp_dir().join(format!("r3-fake-live-{pid}"));
    let _ = fs::remove_dir_all(&fake_live);
    fs::create_dir_all(fake_live.join(".local/share/elastos")).unwrap();
    fs::write(fake_live.join("HOME-MARKER"), b"this is not isolation\n").unwrap();
    let link = iso.join(format!("live-via-symlink-{pid}"));
    symlink(&fake_live, &link).unwrap();
    match a12::check_tmp_root(&link) {
        Ok(()) => {
            let write = a12::create_plain_leftover(&link, "escaped.txt", b"through-symlink\n");
            let escaped = fake_live.join("storage").join("escaped.txt");
            let wrote_outside = escaped.is_file();
            let _ = fs::remove_dir_all(&fake_live);
            let _ = fs::remove_file(&link);
            hunt(
                "guard-live-home-symlink",
                if wrote_outside { "SURVIVED" } else { "CAUGHT" },
                &format!(
                    "check_tmp_root accepted symlink under isolation; write={write:?} escaped={}",
                    escaped.display()
                ),
            );
        }
        Err(reason) => {
            let _ = fs::remove_dir_all(&fake_live);
            let _ = fs::remove_file(&link);
            hunt("guard-live-home-symlink", "CAUGHT", &reason);
        }
    }
}

#[test]
fn r3_guard_home_via_symlink_env() {
    let iso = a12::isolation_root();
    if let Ok(home) = std::env::var("HOME") {
        if home.is_empty() {
            hunt("guard-home-symlink-env", "INCONCLUSIVE", "HOME empty");
            return;
        }
        let link = iso.join(format!("home-link-{}", std::process::id()));
        let _ = fs::remove_file(&link);
        if symlink(&home, &link).is_err() {
            hunt("guard-home-symlink-env", "INCONCLUSIVE", "could not symlink HOME");
            return;
        }
        match a12::check_tmp_root(&link) {
            Ok(()) => hunt(
                "guard-home-symlink-env",
                "SURVIVED",
                "ELASTOS_TMP_ROOT may be a symlink to $HOME if the link sits under isolation",
            ),
            Err(reason) => hunt("guard-home-symlink-env", "CAUGHT", &reason),
        }
        let _ = fs::remove_file(&link);
    } else {
        hunt("guard-home-symlink-env", "INCONCLUSIVE", "HOME unset");
    }
}

#[test]
fn r3_ra6_journey_is_blocked_today() {
    match a6::resident_two_instance_token_journey() {
        a6::JourneyStatus::Blocked { ask, reason } => hunt(
            "ra6-current",
            "BLOCKED",
            &format!("ask={ask} reason={reason}"),
        ),
        a6::JourneyStatus::Pass(line) => hunt(
            "ra6-current",
            "SURVIVED",
            &format!("PASS without hosting two resident instances: {line}"),
        ),
        a6::JourneyStatus::Fail(line) => hunt("ra6-current", "FAIL", &line),
    }
}

#[test]
fn r3_presence_census_is_not_created_set() {
    let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a12.rs"));
    let default_uses_under = source.contains(
        "pub fn runtime_temp_census() -> Result<String, String> {
    runtime_temp_census_at(&runtime_owned_temp_roots()?)
}",
    );
    let since_exists = source.contains("pub fn runtime_temp_census_since");
    hunt(
        "default-census-api",
        if default_uses_under && since_exists {
            "NOTE"
        } else {
            "INCONCLUSIVE"
        },
        "runtime_temp_census lists present paths; created-set is runtime_temp_census_since only",
    );
}
