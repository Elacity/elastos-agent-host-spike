//! r3 hunts ported to this head, plus r4 hunts.
//! Compiled only inside the #343 worktree for one run. Restored after.

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::a12;
use crate::a6;

fn hunt(id: &str, verdict: &str, detail: &str) {
    println!("HUNT {id}: {verdict} | {detail}");
}

fn isolated_watch(label: &str) -> PathBuf {
    a12::isolated_dir(label)
}

// ---------- r3 hunts, same API they used ----------

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
        if late_in_first { "CAUGHT" } else { "SURVIVED" },
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
        "leftovers_created hides leftovers that were already present when snapshot() ran",
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
            &format!(
                "accepted {} (lexical child of isolation, filesystem parent)",
                escaped.display()
            ),
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
            hunt(
                "guard-home-symlink-env",
                "INCONCLUSIVE",
                "could not symlink HOME",
            );
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

// ---------- r4 hunts: judge the author's "those r3 SURVIVED labels are expected" claim ----------

#[test]
fn r4_late_snapshot_is_refused_by_snapshot_before_runtime() {
    let parent = isolated_watch("r4-late-snap");
    let leftover =
        a12::create_plain_leftover(&parent, "already.txt", b"runtime wrote first\n").expect("write");
    let err = a12::snapshot_before_runtime(&parent);
    a12::remove_isolated(&parent);
    match err {
        Err(reason) if reason.contains("before the Runtime") => hunt(
            "r4-snapshot-before-runtime",
            "CAUGHT",
            &format!("leftover={} reason={reason}", leftover.display()),
        ),
        other => hunt(
            "r4-snapshot-before-runtime",
            "SURVIVED",
            &format!("expected refuse, got {other:?}"),
        ),
    }
}

#[test]
fn r4_run_window_sees_tmpdir_xdg_library() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sandbox = a12::isolation_root().join(format!("r4-window-home-{pid}-{stamp}"));
    let xdg_cache = sandbox.join("xdg-cache");
    fs::create_dir_all(&xdg_cache).unwrap();
    fs::create_dir_all(sandbox.join("Library/Caches")).unwrap();
    let prev_home = std::env::var_os("HOME");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CACHE_HOME", &xdg_cache);
    let before = a12::snapshot_run_window().expect("run-window snapshot");
    let tmp_file = std::env::temp_dir().join(format!("r4-window-tmp-{pid}-{stamp}.txt"));
    let cache_file = xdg_cache.join("outside.txt");
    let lib_file = sandbox.join("Library/Caches").join("outside.txt");
    fs::write(&tmp_file, b"tmpdir leftover\n").unwrap();
    fs::write(&cache_file, b"xdg leftover\n").unwrap();
    fs::write(&lib_file, b"library leftover\n").unwrap();
    let leftovers = a12::leftovers_in_run_window(&before).expect("run-window leftovers");
    let _ = fs::remove_file(&tmp_file);
    match prev_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match prev_cache {
        Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
        None => std::env::remove_var("XDG_CACHE_HOME"),
    }
    a12::remove_isolated(&sandbox);
    let saw = leftovers.contains(&tmp_file)
        && leftovers.contains(&cache_file)
        && leftovers.contains(&lib_file);
    hunt(
        "r4-run-window-siblings",
        if saw { "CAUGHT" } else { "SURVIVED" },
        &format!("leftovers={leftovers:?}"),
    );
}

// ---------- new r4 hunts ----------

#[test]
fn r4_toctou_check_then_swap_symlink() {
    let iso = a12::isolation_root();
    let hold = iso.join(format!("r4-toctou-{}", std::process::id()));
    let _ = fs::remove_dir_all(&hold);
    fs::create_dir_all(&hold).unwrap();
    let first = a12::check_tmp_root(&hold);
    let fake_live = std::env::temp_dir().join(format!("r4-toctou-live-{}", std::process::id()));
    let _ = fs::remove_dir_all(&fake_live);
    fs::create_dir_all(fake_live.join(".local/share/elastos")).unwrap();
    fs::remove_dir_all(&hold).unwrap();
    symlink(&fake_live, &hold).unwrap();
    let second = a12::check_tmp_root(&hold);
    let escaped = fake_live.join("storage").join("escaped.txt");
    let write = a12::create_plain_leftover(&hold, "escaped.txt", b"after-swap\n");
    let wrote_outside = escaped.is_file();
    let _ = fs::remove_file(&hold);
    let _ = fs::remove_dir_all(&fake_live);
    hunt(
        "toctou-check-then-swap",
        match (&first, &second, wrote_outside) {
            (Ok(()), Err(_), true) => "SURVIVED",
            (Ok(()), Err(_), false) => "NOTE",
            _ => "INCONCLUSIVE",
        },
        &format!(
            "first={first:?} second={second:?} write={write:?} wrote_outside={wrote_outside}. \
             Guard re-checks on the next call. A caller that keeps the first Ok path can still write after the swap."
        ),
    );
}

#[test]
fn r4_toctou_missing_dir_becomes_symlink() {
    let iso = a12::isolation_root();
    let hold = iso.join(format!("r4-missing-{}", std::process::id()));
    let _ = fs::remove_file(&hold);
    let _ = fs::remove_dir_all(&hold);
    let first = a12::check_tmp_root(&hold);
    let fake_live = std::env::temp_dir().join(format!("r4-missing-live-{}", std::process::id()));
    let _ = fs::remove_dir_all(&fake_live);
    fs::create_dir_all(fake_live.join(".local/share/elastos")).unwrap();
    symlink(&fake_live, &hold).unwrap();
    let write = a12::create_plain_leftover(&hold, "escaped.txt", b"created-as-link\n");
    let escaped = fake_live.join("storage").join("escaped.txt");
    let wrote_outside = escaped.is_file();
    let second = a12::check_tmp_root(&hold);
    let _ = fs::remove_file(&hold);
    let _ = fs::remove_dir_all(&fake_live);
    hunt(
        "toctou-missing-then-symlink",
        match (&first, wrote_outside) {
            (Ok(()), true) => "SURVIVED",
            (Ok(()), false) => "CAUGHT",
            (Err(_), _) => "CAUGHT",
        },
        &format!(
            "first={first:?} second={second:?} write={write:?} wrote_outside={wrote_outside}"
        ),
    );
}

#[test]
fn r4_bind_mount_capability() {
    hunt(
        "bind-mount-into-census",
        "INCONCLUSIVE",
        "this host refuses mount --bind and unshare -m (Operation not permitted). \
         The guard looks for symlinks and lexical ..; a bind mount is neither.",
    );
}

#[test]
fn r4_hardlink_from_outside_into_watch() {
    let parent = isolated_watch("r4-hard-in");
    let outside = std::env::temp_dir().join(format!("r4-hard-src-{}", std::process::id()));
    fs::write(&outside, b"outside-body\n").unwrap();
    let before = a12::snapshot(&parent).expect("before");
    let link = parent.join("from-outside.txt");
    let linked = fs::hard_link(&outside, &link).is_ok();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|path| path == &link);
    let _ = fs::remove_file(&outside);
    a12::remove_isolated(&parent);
    hunt(
        "hardlink-from-outside",
        if !linked {
            "INCONCLUSIVE"
        } else if found {
            "CAUGHT"
        } else {
            "SURVIVED"
        },
        &format!("linked={linked} found={found} leftovers={leftovers:?}"),
    );
}

#[test]
fn r4_hardlink_escape_then_delete_watch_copy() {
    let parent = isolated_watch("r4-hard-out");
    let before = a12::snapshot(&parent).expect("before");
    let orig = parent.join("keep.txt");
    fs::write(&orig, b"escape-body\n").unwrap();
    let outside = PathBuf::from("/var/tmp").join(format!("r4-hard-escape-{}", std::process::id()));
    let linked = fs::hard_link(&orig, &outside).is_ok();
    fs::remove_file(&orig).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found_inside = leftovers.iter().any(|path| path == &orig);
    let outside_lives = outside.is_file();
    let _ = fs::remove_file(&outside);
    a12::remove_isolated(&parent);
    hunt(
        "hardlink-escape-delete",
        if !linked {
            "INCONCLUSIVE"
        } else if found_inside || !outside_lives {
            "CAUGHT"
        } else {
            "SURVIVED"
        },
        &format!(
            "linked={linked} found_inside={found_inside} outside_lives={outside_lives} leftovers={leftovers:?}"
        ),
    );
}

#[test]
fn r4_write_then_delete_within_window() {
    let parent = isolated_watch("r4-ephemeral");
    let before = a12::snapshot(&parent).expect("before");
    let path = parent.join("gone.txt");
    fs::write(&path, b"was-here\n").unwrap();
    fs::remove_file(&path).unwrap();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "write-then-delete",
        if found { "CAUGHT" } else { "SURVIVED" },
        "snapshot census only sees what still exists at the after-snapshot",
    );
}

#[test]
fn r4_writes_outside_watched_roots() {
    let _lock = a12::lock_real_root();
    let pid = std::process::id();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sandbox = a12::isolation_root().join(format!("r4-outside-home-{pid}-{stamp}"));
    let xdg_cache = sandbox.join("xdg-cache");
    fs::create_dir_all(&xdg_cache).unwrap();
    let prev_home = std::env::var_os("HOME");
    let prev_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CACHE_HOME", &xdg_cache);
    let before = match a12::snapshot_run_window() {
        Ok(snap) => snap,
        Err(reason) => {
            match prev_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match prev_cache {
                Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
            a12::remove_isolated(&sandbox);
            hunt("writes-outside-watch", "INCONCLUSIVE", &reason);
            return;
        }
    };
    let var_tmp = PathBuf::from("/var/tmp").join(format!("r4-var-tmp-{pid}-{stamp}.txt"));
    let shm = PathBuf::from("/dev/shm").join(format!("r4-shm-{pid}-{stamp}.txt"));
    let hidden_cache = sandbox.join(".cache");
    fs::create_dir_all(&hidden_cache).unwrap();
    let cache_default = hidden_cache.join(format!("r4-dot-cache-{pid}.txt"));
    let mut planted = Vec::new();
    for (path, body) in [
        (&var_tmp, b"var-tmp leftover\n".as_slice()),
        (&shm, b"shm leftover\n".as_slice()),
        (&cache_default, b"dot-cache leftover\n".as_slice()),
    ] {
        match fs::write(path, body) {
            Ok(()) => planted.push(path.clone()),
            Err(error) => hunt(
                "writes-outside-watch-plant",
                "INCONCLUSIVE",
                &format!("could not write {}: {error}", path.display()),
            ),
        }
    }
    let leftovers = a12::leftovers_in_run_window(&before).expect("run-window");
    let saw_var = leftovers.iter().any(|p| p == &var_tmp);
    let saw_shm = leftovers.iter().any(|p| p == &shm);
    let saw_dot_cache = leftovers.iter().any(|p| p == &cache_default);
    for path in &planted {
        let _ = fs::remove_file(path);
    }
    match prev_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match prev_cache {
        Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
        None => std::env::remove_var("XDG_CACHE_HOME"),
    }
    a12::remove_isolated(&sandbox);
    hunt(
        "writes-var-tmp",
        if saw_var { "CAUGHT" } else { "SURVIVED" },
        &format!("/var/tmp leftover visible in run-window: {saw_var}"),
    );
    hunt(
        "writes-dev-shm",
        if saw_shm { "CAUGHT" } else { "SURVIVED" },
        &format!("/dev/shm leftover visible in run-window: {saw_shm}"),
    );
    hunt(
        "writes-dot-cache-when-xdg-set",
        if saw_dot_cache { "CAUGHT" } else { "SURVIVED" },
        "XDG_CACHE_HOME was set, so ~/.cache is not in extra_watch_roots",
    );
}

#[test]
fn r4_ctime_same_content_reuse() {
    let parent = isolated_watch("r4-ctime");
    let path = parent.join("slot.txt");
    fs::write(&path, b"same-bytes\n").unwrap();
    let before_ino = fs::symlink_metadata(&path).unwrap().ino();
    let before = a12::snapshot(&parent).expect("before");
    fs::remove_file(&path).unwrap();
    let mut reused = false;
    for _ in 0..300 {
        fs::write(&path, b"same-bytes\n").unwrap();
        if fs::symlink_metadata(&path).unwrap().ino() == before_ino {
            reused = true;
            break;
        }
        fs::remove_file(&path).unwrap();
    }
    if !path.exists() {
        fs::write(&path, b"same-bytes\n").unwrap();
    }
    let _ = Command::new("touch")
        .arg("-r")
        .arg(&path)
        .arg(&path)
        .status();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "ctime-same-content-reuse",
        if found { "CAUGHT" } else { "SURVIVED" },
        &format!("reused={reused} found={found}; touch -r cannot restore ctime on this host"),
    );
}

#[test]
fn r4_large_file_mtime_restore() {
    let parent = isolated_watch("r4-large");
    let path = parent.join("big.bin");
    let first = vec![b'A'; 65 * 1024];
    fs::write(&path, &first).unwrap();
    let before = a12::snapshot(&parent).expect("before");
    let stamp = parent.join("stamp");
    fs::write(&stamp, b"stamp\n").unwrap();
    let _ = Command::new("touch").arg("-r").arg(&path).arg(&stamp).status();
    let mut second = vec![b'B'; 65 * 1024];
    second[0] = b'Z';
    fs::write(&path, &second).unwrap();
    let _ = Command::new("touch").arg("-r").arg(&stamp).arg(&path).status();
    let leftovers = a12::leftovers_created(&before, &parent).expect("created-set");
    let found = leftovers.iter().any(|p| p == &path);
    a12::remove_isolated(&parent);
    hunt(
        "large-file-mtime-restore",
        if found { "CAUGHT" } else { "SURVIVED" },
        "65KiB rewrite, same size, mtime restored; identity should still move via ctime",
    );
}

#[test]
fn r4_detached_child_writes_after_exit() {
    let parent = isolated_watch("r4-detach");
    let leftover = parent.join("after-exit.txt");
    let before = a12::snapshot(&parent).expect("before");
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "sleep 0.8; printf 'late-child\\n' > '{}'",
            leftover.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            a12::remove_isolated(&parent);
            hunt(
                "detached-child-after-exit",
                "INCONCLUSIVE",
                &format!("could not spawn: {error}"),
            );
            return;
        }
    };
    // Census at "Runtime exit": child still asleep.
    std::thread::sleep(Duration::from_millis(50));
    let at_exit = a12::leftovers_created(&before, &parent).expect("at exit");
    let saw_at_exit = at_exit.iter().any(|p| p == &leftover);
    let _ = child.wait_with_output();
    let after = a12::leftovers_created(&before, &parent).expect("after child");
    let saw_after = after.iter().any(|p| p == &leftover);
    a12::remove_isolated(&parent);
    hunt(
        "detached-child-at-exit",
        if saw_at_exit { "CAUGHT" } else { "SURVIVED" },
        "census taken after the parent exits, before the detached child writes",
    );
    hunt(
        "detached-child-later-rescan",
        if saw_after { "CAUGHT" } else { "SURVIVED" },
        "same snapshot, census after the child wrote",
    );
}

#[test]
fn r4_empty_resident_pair_is_fail() {
    match a6::status_after_host_ok(a6::ResidentPair) {
        a6::JourneyStatus::Fail(reason) => hunt("empty-resident-pair", "CAUGHT", &reason),
        other => hunt(
            "empty-resident-pair",
            "SURVIVED",
            &format!("expected FAIL, got {other:?}"),
        ),
    }
}

#[test]
fn r4_guard_var_tmp_is_outside_isolation() {
    match a12::check_tmp_root(Path::new("/var/tmp")) {
        Ok(()) => hunt(
            "guard-var-tmp",
            "SURVIVED",
            "accepted /var/tmp; isolation-under check did not refuse it",
        ),
        Err(reason) => hunt("guard-var-tmp", "CAUGHT", &reason),
    }
}
