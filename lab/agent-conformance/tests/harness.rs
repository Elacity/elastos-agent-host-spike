use agent_conformance::harness::{data_dir, Launch, RunningChild, RunningInstances, ThrowawayHome};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[test]
fn home_is_throwaway() {
    let owned = ThrowawayHome::new().expect("harness must start with the committed fixture");
    let root = owned.root().to_path_buf();
    let lane = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(root.parent(), Some(lane.join("target").as_path()));
    assert!(owned.home().starts_with(&root));
    assert!(owned.data().starts_with(&root));
    assert!(owned.temp().starts_with(&root));
    assert_eq!(
        owned.data(),
        owned.home().join("Library/Application Support/elastos")
    );
    assert_eq!(data_dir(owned.home()).unwrap(), owned.data());
    assert_eq!(owned.guard(owned.home(), owned.data()), Ok(()));
    // All outside inputs are repository paths. The guard never reads them.
    let outside = lane.join("fixtures");
    assert_eq!(
        owned.guard(&outside, owned.data()),
        Err("home is outside the fresh throwaway root")
    );
    assert_eq!(
        owned.guard(owned.home(), &outside),
        Err("data directory is outside the fresh throwaway root")
    );
    for home in [PathBuf::new(), root.clone(), root.join("../escape")] {
        assert_eq!(
            owned.guard(&home, owned.data()),
            Err("home is outside the fresh throwaway root")
        );
    }
    assert_eq!(
        owned.guard(owned.home(), &root.join("wrong-data")),
        Err("data directory does not match the macOS Home rule")
    );
    assert_eq!(
        ThrowawayHome::create_at(&root).unwrap_err(),
        "throwaway root is not fresh"
    );
    assert_eq!(
        ThrowawayHome::create_at(&outside).unwrap_err(),
        "throwaway root must be directly inside the lane target"
    );
    #[cfg(unix)]
    {
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert_eq!(
            owned.guard(&link, owned.data()),
            Err("home must use directories without symlinks")
        );
        assert_eq!(
            owned.guard(owned.home(), &link.join("data")),
            Err("data directory must use directories without symlinks")
        );
        fs::remove_file(link).unwrap();
        fs::remove_dir(owned.temp()).unwrap();
        std::os::unix::fs::symlink(&outside, owned.temp()).unwrap();
        // A bad TMPDIR is refused before even trying to start this absent tool.
        assert_eq!(
            owned
                .launch(&root.join("absent-tool"), &[], Duration::from_secs(1))
                .err(),
            Some("temp directory must use directories without symlinks")
        );
        fs::remove_file(owned.temp()).unwrap();
        fs::create_dir(owned.temp()).unwrap();
    }
    let second = ThrowawayHome::new().unwrap();
    assert_ne!(second.root(), owned.root());
    second.finish().unwrap();
    owned.finish().unwrap();
    assert!(!root.exists(), "passed test root must be removed");
}

#[test]
fn launch_env_is_only_the_throwaway_home() {
    let owned = ThrowawayHome::new().unwrap();
    let output = owned
        .launch(Path::new("/usr/bin/env"), &[], Duration::from_secs(2))
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let lines: Vec<_> = text.lines().collect();
    // Do not print captured values on failure: a broken env_clear could have
    // passed private parent values. F-ac1d runs with a synthetic parent env.
    assert!(
        lines.len() == 4,
        "child environment must have exactly four entries"
    );
    for expected in [
        format!("HOME={}", owned.home().display()),
        format!("TMPDIR={}", owned.temp().display()),
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin".to_owned(),
        "ELASTOS_CARRIER_MDNS=0".to_owned(),
    ] {
        assert!(
            lines.contains(&expected.as_str()),
            "required child environment entry is missing"
        );
    }
    let output = owned
        .launch(
            Path::new("/bin/sh"),
            &[
                "-c",
                "if read line; then exit 99; fi; printf out; printf err >&2; exit 7",
            ],
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
    owned.finish().unwrap();
}

#[test]
fn launch_stops_a_child_past_its_bound() {
    let owned = ThrowawayHome::new().unwrap();
    let started = Instant::now();
    let output = owned.launch(Path::new("/bin/sleep"), &["3"], Duration::from_secs(1));
    assert_eq!(output.err(), Some("child exceeded its time bound"));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "child must be stopped within a few seconds"
    );
    owned.finish().unwrap();
}

fn child_group(home: &ThrowawayHome) -> RunningChild<'_> {
    let child = home
        .start(
            Path::new("/bin/sh"),
            &[
                "-c",
                "trap 'kill -TERM \"$child\"; wait; exit 0' TERM; /bin/sleep 30 & child=$!; wait",
            ],
        )
        .unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        let output = home
            .launch(
                Path::new("/usr/bin/pgrep"),
                &["-g", &child.pgid().to_string()],
                Duration::from_secs(1),
            )
            .unwrap();
        if output.status.success()
            && std::str::from_utf8(&output.stdout).unwrap().lines().count() == 2
        {
            return child;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("fixture parent and child must share the managed process group");
}

#[test]
fn managed_child_stop_reaps_its_process_group() {
    let home = ThrowawayHome::new().unwrap();
    let mut child = child_group(&home);
    assert!(child.is_alive().unwrap());
    let pgid = child.pgid();
    child
        .stop()
        .expect("SIGTERM must stop the parent and its child");
    assert!(!child.is_alive().unwrap());
    assert!(!home.group_is_alive(pgid).unwrap());
    drop(child);
    home.finish().unwrap();
}

#[test]
fn managed_child_drop_kills_its_group_and_keeps_root() {
    let home = ThrowawayHome::new().unwrap();
    let root = home.root().to_path_buf();
    let child = child_group(&home);
    let pgid = child.pgid();
    drop(child);
    assert!(!home.group_is_alive(pgid).unwrap());
    assert!(root.is_dir());
    assert_eq!(
        home.finish(),
        Err("keep the root after an unstopped child or failed stop")
    );
    assert!(root.is_dir());
    // This test has now verified the retained-root policy and empty group.
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parallel_collection_preserves_each_status_and_capture() {
    let homes = [(); 4].map(|_| ThrowawayHome::new().unwrap());
    let ids = ["0", "1", "2", "3"];
    let launches: Vec<_> = homes.iter().zip(ids).map(|(home, id)| Launch {
        home,
        program: Path::new("/bin/sh"),
        args: vec!["-c", "touch ready; while [ ! -f release ]; do /bin/sleep 0.01; done; printf 'out%s' \"$1\"; printf 'err%s' \"$1\" >&2; exit \"$1\"", "fixture", id],
    }).collect();
    let running = RunningInstances::start(&launches, None).unwrap();
    let started = Instant::now();
    while homes.iter().any(|home| !home.home().join("ready").exists()) {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "all children must start before any collection"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for home in &homes {
        fs::write(home.home().join("release"), b"").unwrap();
    }
    let completions = running.collect(Duration::from_secs(5)).unwrap();
    assert_eq!(completions.len(), 4);
    for (index, completion) in completions.iter().enumerate() {
        assert_eq!(completion.output.status.code(), Some(index as i32));
        assert_eq!(completion.output.stdout, format!("out{index}").as_bytes());
        assert_eq!(completion.output.stderr, format!("err{index}").as_bytes());
        assert!(completion.elapsed < Duration::from_secs(5));
    }
    for home in homes {
        home.finish().unwrap();
    }
}

#[test]
fn parallel_timeout_is_failure_and_reaps_every_group() {
    let homes = [(); 2].map(|_| ThrowawayHome::new().unwrap());
    let launches: Vec<_> = homes
        .iter()
        .map(|home| Launch {
            home,
            program: Path::new("/bin/sh"),
            args: vec!["-c", "printf '%s' \"$$\" > pid; exec /bin/sleep 3"],
        })
        .collect();
    let running = RunningInstances::start(&launches, None).unwrap();
    let started = Instant::now();
    let result = running.collect(Duration::from_secs(1));
    let reason = result.err();
    for home in homes {
        let pgid = fs::read_to_string(home.home().join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(!home.group_is_alive(pgid).unwrap());
        let root = home.root().to_path_buf();
        let finish = home.finish();
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
        assert_eq!(
            finish,
            Err("keep the root after an unstopped child or failed stop")
        );
    }
    assert_eq!(
        reason,
        Some("instances exceeded their shared time bound; harness cleanup is not a Runtime stop")
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn parallel_attach_uses_only_guarded_fixture_coordinates() {
    let operator = ThrowawayHome::new().unwrap();
    let home = ThrowawayHome::new().unwrap();
    let launches = [Launch {
        home: &home,
        program: Path::new("/usr/bin/env"),
        args: vec![],
    }];
    let result = RunningInstances::start(&launches, Some(&operator))
        .unwrap()
        .collect(Duration::from_secs(2))
        .unwrap();
    let output = &result[0].output;
    assert!(output.status.success() && output.stderr.is_empty());
    let env = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(
        env.lines().count(),
        5,
        "attached child environment must have five entries"
    );
    for expected in [
        format!("HOME={}", home.home().display()),
        format!("TMPDIR={}", home.temp().display()),
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin".into(),
        "ELASTOS_CARRIER_MDNS=0".into(),
        format!(
            "ELASTOS_RUNTIME_COORDS_FILE={}",
            operator.data().join("runtime-coords.json").display()
        ),
    ] {
        assert!(
            env.lines().any(|line| line == expected),
            "required fixture environment entry is missing"
        );
    }
    // No coordinates content is created or read. A damaged operator guard must
    // refuse even a harmless env command before starting any client.
    fs::remove_dir(operator.temp()).unwrap();
    std::os::unix::fs::symlink(home.temp(), operator.temp()).unwrap();
    let refused = RunningInstances::start(&launches, Some(&operator)).err();
    fs::remove_file(operator.temp()).unwrap();
    fs::create_dir(operator.temp()).unwrap();
    assert_eq!(
        refused,
        Some("temp directory must use directories without symlinks")
    );
    home.finish().unwrap();
    operator.finish().unwrap();
}

#[test]
fn parallel_collection_refuses_live_descendants() {
    let home = ThrowawayHome::new().unwrap();
    let launches = [Launch {
        home: &home,
        program: Path::new("/bin/sh"),
        args: vec!["-c", "printf '%s' \"$$\" > pid; /bin/sleep 30 & exit 0"],
    }];
    let result = RunningInstances::start(&launches, None)
        .unwrap()
        .collect(Duration::from_secs(2));
    let pgid = fs::read_to_string(home.home().join("pid"))
        .unwrap()
        .parse()
        .unwrap();
    let alive = home.group_is_alive(pgid).unwrap();
    // Settle the planted missing-drain check too, before failing the assertion.
    if alive {
        home.launch(
            Path::new("/bin/kill"),
            &["-KILL", &format!("-{pgid}")],
            Duration::from_secs(1),
        )
        .unwrap();
        let started = Instant::now();
        while home.group_is_alive(pgid).unwrap() {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(
        result.err(),
        Some("completed child left a live process group")
    );
    assert!(!alive, "collection failure must clean every descendant");
    let root = home.root().to_path_buf();
    assert_eq!(
        home.finish(),
        Err("keep the root after an unstopped child or failed stop")
    );
    fs::remove_dir_all(root).unwrap();
}
