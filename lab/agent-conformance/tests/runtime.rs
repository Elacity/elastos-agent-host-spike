use agent_conformance::harness::ThrowawayHome;
use agent_conformance::runtime::runtime_under_test;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn assert_operator_refusal(home: &ThrowawayHome) {
    let runtime = runtime_under_test();
    // launch runs from this Home. A relative fixture path keeps operator-local
    // checkout paths out of Runtime's log and the recorded stderr evidence.
    let to_lane: PathBuf = home
        .home()
        .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap()
        .components()
        .map(|_| "..")
        .collect();
    let probe = to_lane.join("probe");
    let output = home
        .launch(
            &runtime.binary,
            &["run", probe.to_str().unwrap()],
            Duration::from_secs(10),
        )
        .expect("Runtime must exit within the launch bound");
    let stderr = std::str::from_utf8(&output.stderr).expect("Runtime stderr must be UTF-8");
    assert!(
        !output.status.success(),
        "Runtime must refuse without an operator"
    );
    assert!(
        stderr.contains("This command requires a running runtime."),
        "Runtime must give the operator refusal reason; stderr:\n{stderr}"
    );
    println!("Runtime refusal stderr:\n{stderr}");
}

#[test]
fn run_without_operator_is_refused_with_reason() {
    let home = ThrowawayHome::new().unwrap();
    assert_operator_refusal(&home);
    home.finish().unwrap();
}

#[test]
fn runtime_data_dir_is_under_throwaway_home() {
    let home = ThrowawayHome::new().unwrap();
    let decoy = home.data().join("runtime-coords.json");
    // Documentation-only destination. Runtime rejects it before a network
    // client or PID check. These values belong only to this disposable fixture.
    fs::write(
        &decoy,
        br#"{"api_url":"http://192.0.2.1:9","attach_secret":"dummy","pid":0}"#,
    )
    .unwrap();
    assert!(decoy.is_file(), "decoy must exist before Runtime starts");
    assert_operator_refusal(&home);
    assert!(
        !decoy.try_exists().unwrap(),
        "Runtime must remove the decoy from the guarded data directory"
    );
    home.finish().unwrap();
}
