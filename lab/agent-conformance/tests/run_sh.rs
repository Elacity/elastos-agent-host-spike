//! Drives the real `run.sh` against a stand-in Cargo and a stand-in installed
//! binary. `run.sh` is the only writer of the launch record, and the record's
//! path never reaches a test process: these tests observe both.

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
    }

    fn run(&self) -> Output {
        let path = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.bin.display());
        Command::new(self.lane.join("run.sh"))
            .env_remove("AGENT_CONFORMANCE_LAUNCH_RECORD")
            .env("PATH", path)
            .env("AGENT_CONFORMANCE_INSTALLED_BINARY", &self.installed)
            .env("AGENT_CONFORMANCE_INSTALLED_DATA", &self.data)
            .env("TEST_REAL_REPORT", env!("CARGO_BIN_EXE_report"))
            .env("TEST_SUITE_ENV", &self.suite_env)
            .env("TEST_REPORT_ARGS", &self.report_args)
            .env("TEST_REPORT_ENV", self.repo.join("report-env"))
            .output()
            .unwrap()
    }

    fn record_path(&self, output: &Output) -> PathBuf {
        let stdout = String::from_utf8(output.stdout.clone()).unwrap();
        let line = stdout
            .lines()
            .find(|line| line.starts_with("launch record file: "))
            .unwrap_or_else(|| panic!("no launch record line in {stdout:?}"));
        PathBuf::from(
            line["launch record file: ".len()..]
                .split(" (")
                .next()
                .unwrap(),
        )
    }

    fn suite_environment(&self) -> String {
        fs::read_to_string(&self.suite_env).unwrap()
    }

    fn report_record_argument(&self) -> String {
        let args = fs::read_to_string(&self.report_args).unwrap();
        args.lines().last().unwrap().to_owned()
    }

    fn record(&self, output: &Output) -> (PathBuf, String) {
        let path = self.record_path(output);
        let text = fs::read_to_string(&path).unwrap();
        (path, text)
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

/// Stand-in Cargo: it writes the report wrapper, and records the environment
/// every test process would inherit.
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
        exit 0
        ;;
esac
exit 0
"#;

const ANSWERING: &str = "#!/bin/sh\necho 'elastos 9.9.9'\n";

#[test]
fn run_sh_writes_one_record_only_after_the_installed_binary_answers() {
    let mut lane = Lane::new();
    lane.install(ANSWERING.as_bytes());
    let output = lane.run();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(
        output.status.success(),
        "stderr {:?}; stdout {stdout:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let binary = sha256(ANSWERING.as_bytes());
    assert!(
        stdout.contains(&format!(
            "installed launch: expected hash {binary}, first hash {binary}, second hash {binary}\n"
        )),
        "{stdout:?}"
    );
    let (path, record) = lane.record(&output);
    assert_eq!(
        record,
        format!(
            "path={} sha256={} answer=elastos 9.9.9\n",
            fs::canonicalize(&lane.installed).unwrap().display(),
            binary
        )
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
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
    assert_eq!(lane.report_record_argument(), path.display().to_string());
}

#[test]
fn a_binary_that_changes_between_the_two_hashes_leaves_no_record() {
    let changing = "#!/bin/sh\nprintf '\\n# changed\\n' >> \"$0\"\necho 'elastos 9.9.9'\n";
    let mut lane = Lane::new();
    lane.install(changing.as_bytes());
    let output = lane.run();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
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
    let (path, record) = lane.record(&output);
    assert!(record.is_empty(), "{record:?}");
    assert!(
        !lane
            .suite_environment()
            .contains(&path.display().to_string()),
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
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
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
    let (path, record) = lane.record(&output);
    assert!(record.is_empty(), "{record:?}");
    assert!(
        !lane
            .suite_environment()
            .contains(&path.display().to_string()),
        "{}",
        lane.suite_environment()
    );
}

#[test]
fn a_binary_that_answers_without_a_version_leaves_no_record() {
    let mut lane = Lane::new();
    lane.install(b"#!/bin/sh\necho 'hello'\n");
    let output = lane.run();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
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
    let (path, record) = lane.record(&output);
    assert!(record.is_empty(), "{record:?}");
    assert!(
        !lane
            .suite_environment()
            .contains(&path.display().to_string()),
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
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
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
    let (_, record) = lane.record(&output);
    assert!(record.is_empty(), "{record:?}");
}
