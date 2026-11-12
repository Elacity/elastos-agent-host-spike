//! Drives the real `run.sh` against a stand-in Cargo and a stand-in installed
//! binary. `run.sh` is the only writer of the launch record, writes it only
//! after the suite has finished, and gives its path to no test process: these
//! tests observe all of that, including a record a test plants where the old
//! code used to keep one.

use agent_conformance::identity::sha256;
use agent_conformance::report::release_platform;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A copied lane in its own repository, so `run.sh` writes its target folder
/// there and never into this checkout's target.
struct Lane {
    _root: tempfile::TempDir,
    repo: PathBuf,
    lane: PathBuf,
    bin: PathBuf,
    installed: PathBuf,
    data: PathBuf,
    suite_env: PathBuf,
    report_args: PathBuf,
    launch_log: PathBuf,
    suite_marker: PathBuf,
    suite_pid_file: PathBuf,
    linger: bool,
    rewrite_reporter: bool,
}

impl Lane {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let lane = repo.join("lab/agent-conformance");
        fs::create_dir_all(&lane).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("run.sh"),
            lane.join("run.sh"),
        )
        .unwrap();
        fs::write(lane.join("Cargo.toml"), "[package]\nname = \"stand-in\"\n").unwrap();
        fs::write(repo.join(".gitignore"), "/target/\n").unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["add", "-A"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=stand-in",
                "-c",
                "user.email=stand-in@example.invalid",
                "commit",
                "-q",
                "-m",
                "stand-in lane",
            ],
        );
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        fs::write(&cargo, CARGO).unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        let suite_env = root.path().join("suite-env");
        let report_args = root.path().join("report-args");
        Self {
            _root: root,
            repo,
            lane,
            bin,
            installed: PathBuf::new(),
            data: PathBuf::new(),
            suite_env,
            report_args,
            launch_log: PathBuf::new(),
            suite_marker: PathBuf::new(),
            suite_pid_file: PathBuf::new(),
            linger: false,
            rewrite_reporter: false,
        }
    }

    /// Writes the stand-in binary and the installed records that hash it.
    fn install(&mut self, bytes: &[u8]) {
        let installed = self.repo.join("installed/bin/elastos");
        let data = self.repo.join("installed/data");
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        fs::create_dir_all(data.join("installation")).unwrap();
        fs::write(&installed, bytes).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(data.join("components.json"), b"{\"capsules\":{}}").unwrap();
        let binary = sha256(bytes);
        let release = serde_json::json!({ "payload": {
            "version": "2.0.1",
            "source": { "commit": format!("{:040x}", 1) },
            "platforms": { release_platform(): {
                "binary": { "sha256": binary },
                "components": { "sha256": sha256(b"{\"capsules\":{}}") } } } } })
        .to_string()
        .into_bytes();
        let head = serde_json::json!({ "payload": {
            "version": "2.0.1", "release_sha256": sha256(&release) } })
        .to_string();
        fs::write(data.join("installation/release.json"), &release).unwrap();
        fs::write(data.join("installation/release-head.json"), head).unwrap();
        self.installed = installed;
        self.data = data;
        self.launch_log = self._root.path().join("launch-log");
        self.suite_marker = self._root.path().join("suite-marker");
        self.suite_pid_file = self._root.path().join("suite-pids");
    }

    fn run(&self) -> Output {
        let path = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.bin.display());
        let mut command = Command::new(self.lane.join("run.sh"));
        command
            .env_remove("AGENT_CONFORMANCE_LAUNCH_RECORD")
            .env("PATH", path)
            .env("AGENT_CONFORMANCE_INSTALLED_BINARY", &self.installed)
            .env("AGENT_CONFORMANCE_INSTALLED_DATA", &self.data)
            .env("TEST_REAL_REPORT", env!("CARGO_BIN_EXE_report"))
            .env("TEST_SUITE_ENV", &self.suite_env)
            .env("TEST_REPORT_ARGS", &self.report_args)
            .env("TEST_REPORT_ENV", self.repo.join("report-env"))
            .env("TEST_LAUNCH_LOG", &self.launch_log)
            .env("TEST_SUITE_MARKER", &self.suite_marker)
            .env("TEST_SUITE_PID_FILE", &self.suite_pid_file);
        if self.linger {
            command.env("TEST_SUITE_LINGER", "1");
        }
        if self.rewrite_reporter {
            command.env("TEST_REWRITE_REPORTER", "1");
        }
        command.output().unwrap()
    }

    fn stdout(&self, output: &Output) -> String {
        String::from_utf8(output.stdout.clone()).unwrap()
    }

    /// The receipt's `launch record file:` line.
    fn record_line(&self, output: &Output) -> String {
        let stdout = self.stdout(output);
        stdout
            .lines()
            .find(|line| line.starts_with("launch record file: "))
            .unwrap_or_else(|| panic!("no launch record line in {stdout:?}"))
            .to_owned()
    }

    /// The path the receipt says the record was written to; `None` when the
    /// receipt says no record was made.
    fn record_path(&self, output: &Output) -> Option<PathBuf> {
        let line = self.record_line(output);
        let path = line["launch record file: ".len()..]
            .split(" (")
            .next()
            .unwrap();
        (path != "none").then(|| PathBuf::from(path))
    }

    /// The record text copied into the receipt output, which stays after the
    /// record folder is removed.
    fn record_contents(&self, output: &Output) -> String {
        let stdout = self.stdout(output);
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("launch record contents: "))
            .unwrap_or_else(|| panic!("no launch record contents in {stdout:?}"))
            .to_owned()
    }

    /// Any folder under the lane target that holds launch records: none may
    /// appear, whatever a test planted there.
    fn record_folders(&self) -> Vec<String> {
        fs::read_dir(self.lane.join("target"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("launch-record."))
            .collect()
    }

    fn suite_environment(&self) -> String {
        fs::read_to_string(&self.suite_env).unwrap()
    }

    fn report_arguments(&self) -> Vec<String> {
        fs::read_to_string(&self.report_args)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn assert_no_record(&self, output: &Output) {
        assert_eq!(
            self.record_line(output),
            "launch record file: none (0 record(s), mode -)"
        );
        assert_eq!(self.record_contents(output), "");
        assert_eq!(
            self.report_arguments().len(),
            4,
            "{:?}",
            self.report_arguments()
        );
    }
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// Stand-in Cargo: it writes the report wrapper, records the environment every
/// test process would inherit, marks that the suite ran, and, when asked,
/// leaves a process behind in its group.
const CARGO: &str = r#"#!/bin/sh
target=${CARGO_TARGET_DIR:?}
case "$1" in
    build)
        mkdir -p "$target/debug"
        cat >"$target/debug/report" <<'WRAPPER'
#!/bin/sh
if [ "$1" = "--installed-binary-hash" ]; then exec "$TEST_REAL_REPORT" "$@"; fi
if [ "$1" = "--check-earlier-runs" ]; then exit 0; fi
printf '%s\n' "$@" > "$TEST_REPORT_ARGS"
env > "$TEST_REPORT_ENV"
exit 0
WRAPPER
        chmod 700 "$target/debug/report"
        exit 0
        ;;
    test)
        env > "$TEST_SUITE_ENV"
        : > "$TEST_SUITE_MARKER"
        if [ -n "${TEST_REWRITE_REPORTER:-}" ]; then
            cat >"$target/debug/report" <<'REPLACEMENT'
#!/bin/sh
printf 'installed_runtime_ran (A14) | PASS\n'
printf 'launch record file: none (0 record(s), mode -)\n'
exit 0
REPLACEMENT
            chmod 700 "$target/debug/report"
        fi
        if [ -n "${TEST_SUITE_LINGER:-}" ]; then
            sleep 60 &
            echo $! >> "$TEST_SUITE_PID_FILE"
        fi
        exit 0
        ;;
esac
exit 0
"#;

/// Answers with a version and records whether the suite had already run when
/// it was launched.
const ANSWERING: &str = r#"#!/bin/sh
if [ -n "${TEST_LAUNCH_LOG:-}" ]; then
    if [ -e "${TEST_SUITE_MARKER:-/nonexistent}" ]; then
        printf 'after-suite\n' >>"$TEST_LAUNCH_LOG"
    else
        printf 'before-suite\n' >>"$TEST_LAUNCH_LOG"
    fi
fi
echo 'elastos 9.9.9'
"#;

#[test]
fn run_sh_writes_one_record_only_after_the_suite_and_the_installed_binary_answer() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The installed binary was launched after the suite, not before it.
    assert_eq!(
        fs::read_to_string(&lane.launch_log).unwrap(),
        "after-suite\n"
    );
    let binary = sha256(ANSWERING.as_bytes());
    assert!(
        stdout.contains(&format!(
            "installed launch: expected hash {binary}, first hash {binary}, second hash {binary}\n"
        )),
        "{stdout:?}"
    );
    let path = lane
        .record_path(&output)
        .unwrap_or_else(|| panic!("no record path in {stdout:?}"));
    assert_eq!(
        lane.record_contents(&output),
        format!(
            "path={} sha256={} answer=elastos 9.9.9",
            fs::canonicalize(&lane.installed).unwrap().display(),
            binary
        )
    );
    assert_eq!(
        lane.record_line(&output),
        format!(
            "launch record file: {} (1 record(s), mode 600)",
            path.display()
        )
    );
    // The record folder is outside everything the suite was given, and is
    // removed once the report has read it; the receipt output keeps the copy.
    assert!(!path.starts_with(&lane.repo), "{}", path.display());
    assert!(!path.exists(), "{}", path.display());
    assert_eq!(lane.record_folders(), Vec::<String>::new());
    // The suite's environment never names the record: no variable and no value.
    let suite = lane.suite_environment();
    assert!(
        !suite
            .lines()
            .any(|line| line.starts_with("AGENT_CONFORMANCE_LAUNCH_RECORD=")),
        "{suite}"
    );
    assert!(!suite.contains(&path.display().to_string()), "{suite}");
    // The report is given the path on its command line, after the suite.
    let arguments = lane.report_arguments();
    assert_eq!(arguments.len(), 5, "{arguments:?}");
    assert_eq!(arguments.last().unwrap(), &path.display().to_string());
}

#[test]
fn a_binary_that_changes_between_the_two_hashes_leaves_no_record() {
    let changing = "#!/bin/sh\nprintf '\\n# changed\\n' >> \"$0\"\necho 'elastos 9.9.9'\n";
    let mut lane = Lane::new();
    lane.install(changing.as_bytes());
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout
            .contains("launch record: none; the installed binary changed between the two hashes\n"),
        "{stdout:?}"
    );
    lane.assert_no_record(&output);
    assert_eq!(lane.record_folders(), Vec::<String>::new());
    assert!(
        !lane
            .suite_environment()
            .contains("AGENT_CONFORMANCE_LAUNCH_RECORD"),
        "{}",
        lane.suite_environment()
    );
}

#[test]
fn a_binary_that_fails_to_start_leaves_no_record() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    fs::set_permissions(&lane.installed, fs::Permissions::from_mode(0o600)).unwrap();
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout
            .contains("launch record: none; the installed binary did not answer with a version\n"),
        "{stdout:?}"
    );
    lane.assert_no_record(&output);
    assert_eq!(lane.record_folders(), Vec::<String>::new());
    assert!(
        !lane
            .suite_environment()
            .contains("AGENT_CONFORMANCE_LAUNCH_RECORD"),
        "{}",
        lane.suite_environment()
    );
}

#[test]
fn a_binary_that_answers_without_a_version_leaves_no_record() {
    let mut lane = Lane::new();
    lane.install(b"#!/bin/sh\necho 'hello'\n");
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout
            .contains("launch record: none; the installed binary did not answer with a version\n"),
        "{stdout:?}"
    );
    lane.assert_no_record(&output);
    assert_eq!(lane.record_folders(), Vec::<String>::new());
    assert!(
        !lane
            .suite_environment()
            .contains("AGENT_CONFORMANCE_LAUNCH_RECORD"),
        "{}",
        lane.suite_environment()
    );
}

#[test]
fn run_sh_writes_no_record_when_the_installed_binary_does_not_match_its_record() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    // The installed record names other bytes than the file holds.
    fs::write(
        &lane.installed,
        b"#!/bin/sh\necho 'elastos 9.9.9'\n# other\n",
    )
    .unwrap();
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(
            "launch record: none; the installed binary does not match its installed record\n"
        ),
        "{stdout:?}"
    );
    lane.assert_no_record(&output);
    assert_eq!(lane.record_folders(), Vec::<String>::new());
}

#[test]
fn a_pre_created_record_at_the_old_location_is_no_evidence() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    // A test can write anywhere under the lane, including the place the record
    // used to sit: plant the exact line a passing record would hold there.
    let planted_dir = lane.lane.join("target/launch-record.planted");
    fs::create_dir_all(&planted_dir).unwrap();
    let planted = format!(
        "path={} sha256={} answer=elastos 9.9.9\n",
        fs::canonicalize(&lane.installed).unwrap().display(),
        sha256(ANSWERING.as_bytes())
    );
    fs::write(planted_dir.join("launches"), &planted).unwrap();
    // The installed record names other bytes, so no launch can qualify and a
    // record could come only from the planted file.
    fs::write(
        &lane.installed,
        b"#!/bin/sh\necho 'elastos 9.9.9'\n# other\n",
    )
    .unwrap();
    let output = lane.run();
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(
            "launch record: none; the installed binary does not match its installed record\n"
        ),
        "{stdout:?}"
    );
    lane.assert_no_record(&output);
    // The planted file stays exactly as the test left it, and no record folder
    // of `run.sh`'s appeared beside it.
    assert_eq!(
        fs::read_to_string(planted_dir.join("launches")).unwrap(),
        planted
    );
    assert_eq!(
        lane.record_folders(),
        vec!["launch-record.planted".to_owned()]
    );
    assert!(
        lane.report_arguments()
            .iter()
            .all(|argument| !argument.contains("launch-record")),
        "{:?}",
        lane.report_arguments()
    );
}

#[test]
fn a_lingering_suite_process_makes_run_sh_refuse_to_record() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    lane.linger = true;
    let output = lane.run();
    // The stand-in suite's processes outlive it; stop them before asserting.
    let pids = fs::read_to_string(&lane.suite_pid_file)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(!pids.is_empty(), "the stand-in suite left no process");
    for pid in &pids {
        let _ = Command::new("kill").args(["-9", pid]).status();
    }
    let stdout = lane.stdout(&output);
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("launch record: none; a process started for the suite is still alive\n"),
        "{stdout:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("suite process still alive: process group "),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    lane.assert_no_record(&output);
    assert_eq!(lane.record_folders(), Vec::<String>::new());
    // The installed binary was never launched.
    assert!(!lane.launch_log.exists(), "{}", lane.launch_log.display());
}

#[test]
fn a_suite_that_rewrites_the_reporter_makes_run_sh_refuse() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    // The suite writes the folder the report was built in. Here it replaces the
    // report with one that prints a PASS without launching anything.
    lane.rewrite_reporter = true;
    let output = lane.run();
    let stdout = lane.stdout(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stdout {stdout:?}");
    let line = stderr
        .lines()
        .find(|line| line.starts_with("reporter changed during the suite: "))
        .unwrap_or_else(|| panic!("no refusal in {stderr:?}"));
    let hashes: Vec<_> = line["reporter changed during the suite: ".len()..]
        .split_whitespace()
        .collect();
    assert_eq!(hashes.len(), 2, "{line:?}");
    for hash in &hashes {
        assert_eq!(hash.len(), 64, "{line:?}");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "{line:?}");
    }
    assert_ne!(hashes[0], hashes[1], "{line:?}");
    // No row and no record: the replaced report never ran, and the installed
    // binary was never launched.
    assert!(!stdout.contains("PASS"), "{stdout:?}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(!lane.launch_log.exists(), "{}", lane.launch_log.display());
    assert!(!lane.report_args.exists(), "{}", lane.report_args.display());
    assert_eq!(lane.record_folders(), Vec::<String>::new());
}
