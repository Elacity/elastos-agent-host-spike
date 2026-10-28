//! The one lab launch of a provider under a caller-written confinement profile.
//!
//! A PASS here gives the Runtime no C0 credit and no B3 credit.

use agent_conformance::harness::{ChildInput, ThrowawayHome};
use agent_conformance::standin_runtime::{
    start_provider, HostPrimitive, HostReport, StartedProvider, STDIN_BYTE_LIMIT,
};
use serde_json::json;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

const PROVIDER_NAME: &str = "wallet-provider";
const WRITE_GRANT: &str = "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))";
const READ_GRANT: &str = "(allow file-read* (subpath (param \"STORAGE_ROOT\")))";

fn require_confinement_tool() -> &'static Path {
    assert_eq!(
        std::env::consts::OS,
        "macos",
        "setup: provider launch is exercised on macos"
    );
    let tool = Path::new("/usr/bin/sandbox-exec");
    assert!(
        tool.is_file(),
        "setup: the confinement tool /usr/bin/sandbox-exec is absent"
    );
    tool
}

fn wallet_provider_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(build_wallet_provider_binary)
}

fn build_wallet_provider_binary() -> PathBuf {
    let target = agent_conformance::build::lane().join("target/wallet-provider");
    let manifest =
        agent_conformance::build::repository().join("capsules/wallet-provider/Cargo.toml");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = agent_conformance::build::offline_build(&cargo, &target)
        .unwrap_or_else(|err| panic!("setup: wallet-provider build must start: {err}"));
    let output = command
        .arg("build")
        .arg("--locked")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--bin")
        .arg("wallet-provider")
        .arg("--message-format=json")
        .output()
        .unwrap_or_else(|err| panic!("setup: wallet-provider build must start: {err}"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "setup: wallet-provider build {} must succeed: {stderr}",
        manifest.display()
    );
    let executable = target.join("debug/wallet-provider");
    assert!(
        executable.is_file(),
        "setup: wallet-provider binary {} is absent",
        executable.display()
    );
    executable
}

fn committed_profile() -> PathBuf {
    agent_conformance::build::repository().join("capsules/wallet-provider/confine.sb")
}

fn wallet_dir(base: &Path) -> PathBuf {
    base.join("ElastOS").join("SystemServices").join("Wallet")
}

fn macos_host() -> HostReport {
    HostReport {
        os: "macos",
        unavailable: None,
    }
}

fn fresh_base(home: &ThrowawayHome, name: &str) -> PathBuf {
    let base = home.root().join(name);
    fs::create_dir(&base).expect("the launch base must be created");
    fs::canonicalize(&base).expect("the launch base must resolve")
}

fn write_profile(home: &ThrowawayHome, name: &str, bytes: &[u8]) -> PathBuf {
    let path = home.root().join(name);
    fs::write(&path, bytes).expect("the profile must be written under the home");
    path
}

fn assert_no_child(home: &ThrowawayHome) {
    assert_eq!(
        home.capture_paths().unwrap_err(),
        "capture inventory is empty",
        "a refusal before spawn creates no child"
    );
}

fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a closed port");
    listener.local_addr().expect("a closed port").port()
}

fn start<'a>(
    home: &'a ThrowawayHome,
    binary: &Path,
    base: &Path,
    host: HostReport,
    tool: &Path,
    profile: &Path,
) -> Result<StartedProvider<'a>, String> {
    start_provider(home, binary, base, PROVIDER_NAME, host, tool, profile)
}

fn refused(
    home: &ThrowawayHome,
    binary: &Path,
    base: &Path,
    host: HostReport,
    tool: &Path,
    profile: &Path,
) -> String {
    match start(home, binary, base, host, tool, profile) {
        Ok(_) => panic!("the launch must be refused"),
        Err(reason) => {
            assert!(!reason.is_empty(), "a refusal carries a reason");
            reason
        }
    }
}

/// The caller-written profile is the profile the child runs. `status` answers
/// `ok` before init, so the wallet root and `storage_configured: true` are
/// the init proof.
///
/// Falsifier: F-shared-launch-drop-profile omits `-f` and the profile path.
/// F-shared-launch-bare starts the binary with no confinement tool, so the
/// outside write creates the unrelated directory. F-shared-launch-stub returns
/// Started with a made-up `storage_configured: true` before `init` answers.
#[test]
fn standin_provider_launch_starts_under_caller_profile() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile_bytes =
        fs::read(committed_profile()).expect("the committed profile must be readable");
    let profile = write_profile(&home, "confine.sb", &profile_bytes);
    let base = fresh_base(&home, "wallet-base");
    let wallet = wallet_dir(&base);
    assert!(
        !wallet.exists(),
        "the wallet root is created by init, not by the test"
    );

    let mut started = start(&home, binary, &base, macos_host(), tool, &profile)
        .expect("the caller profile starts the provider");
    assert_eq!(
        started.binary_sha256,
        agent_conformance::identity::sha256(&fs::read(binary).expect("binary bytes")),
        "the launch names the binary by its SHA-256"
    );
    assert_eq!(
        started.profile_sha256,
        agent_conformance::identity::sha256(&profile_bytes),
        "the launch names the caller profile by its SHA-256"
    );
    assert_eq!(started.init["status"], "ok", "init: {}", started.init);
    assert_eq!(
        started.init["data"]["storage_configured"], true,
        "init: {}",
        started.init
    );

    // `status` answers `ok` even before initialization. The live
    // `storage_configured` flag and the wallet root are what init did.
    let status = started
        .request(&json!({ "op": "status" }))
        .expect("status answers");
    assert_eq!(status["status"], "ok", "status: {status}");
    assert!(
        wallet.is_dir() && status["data"]["storage_configured"] == true,
        "init must create the wallet root and report storage_configured true; \
         status before init stays ok with storage_configured false; wallet {} status {status}",
        wallet.display()
    );

    let outside = home.root().parent().expect("lane target").join(format!(
        "outside-wallet-{}",
        home.root()
            .file_name()
            .expect("home name")
            .to_string_lossy()
    ));
    assert!(
        !outside.exists(),
        "the unrelated directory starts absent: {}",
        outside.display()
    );
    let denied = started
        .request(&json!({
            "op": "init",
            "config": { "base_path": outside.display().to_string() }
        }))
        .expect("the confined provider answers an outside init");
    assert_eq!(denied["status"], "error", "outside init: {denied}");
    assert_eq!(denied["code"], "storage_error", "outside init: {denied}");
    let message = denied["message"]
        .as_str()
        .expect("the storage refusal names a reason");
    assert!(
        message.contains("wallet storage"),
        "outside init must name wallet storage: {message}"
    );
    assert!(
        !outside.exists(),
        "an init whose base is outside that home leaves the unrelated directory absent: {}",
        outside.display()
    );

    started.shutdown().expect("shutdown exits 0");
    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("census after the child is reaped");
    assert!(
        census.contains("root checks PASS"),
        "census after reap: {census}"
    );
    home.finish().expect("the passed home is removed");
}

/// A host, tool, or binary the stand-in will not confine creates no child and
/// no storage directory.
///
/// Falsifier: drop the missing-primitive check, replace the Linux sentence,
/// drop the unsupported OS's name, drop the absent-tool check, drop the
/// wrong-tool check, or drop the binary-file check. Each of those leaves this
/// test's matching reason false.
#[test]
fn standin_provider_launch_refuses_unconfined_host() {
    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let base = home.root().join("refused-base");
    let profile = home.root().join("unused-profile");
    let binary = home.root().join("unused-binary");
    let missing_tool = home.root().join("missing-sandbox-exec");
    let missing_binary = home.root().join("missing-wallet-binary");
    let cases = [
        (
            HostReport {
                os: "macos",
                unavailable: Some(HostPrimitive::Landlock),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on macos is refused: linux confinement refused: the kernel has no Landlock",
        ),
        (
            HostReport {
                os: "linux",
                unavailable: Some(HostPrimitive::Landlock),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on linux is refused: linux confinement refused: the kernel has no Landlock",
        ),
        (
            HostReport {
                os: "linux",
                unavailable: Some(HostPrimitive::UserNamespaces),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on linux is refused: linux confinement refused: user namespaces are turned off",
        ),
        (
            HostReport {
                os: "linux",
                unavailable: Some(HostPrimitive::SeccompFilter),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on linux is refused: linux confinement refused: the seccomp filter cannot be installed",
        ),
        (
            HostReport {
                os: "macos",
                unavailable: Some(HostPrimitive::UserNamespaces),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on macos is refused: linux confinement refused: user namespaces are turned off",
        ),
        (
            HostReport {
                os: "macos",
                unavailable: Some(HostPrimitive::SeccompFilter),
            },
            tool,
            binary.as_path(),
            "wallet-provider start on macos is refused: linux confinement refused: the seccomp filter cannot be installed",
        ),
        (
            HostReport {
                os: "linux",
                unavailable: None,
            },
            tool,
            binary.as_path(),
            "wallet-provider start on linux is refused: linux is designed, not enforced, in this lab, so linux is not in DECLARED_CONFINED_OS (macos)",
        ),
        (
            HostReport {
                os: "plan9",
                unavailable: None,
            },
            tool,
            binary.as_path(),
            "wallet-provider start on plan9 is refused: plan9 has no confinement design, and the lab stand-in applies confinement only on macos",
        ),
    ];
    for (host, tool, binary, expected) in cases {
        let reason = refused(&home, binary, &base, host, tool, &profile);
        assert_eq!(reason, expected);
    }

    let absent = refused(&home, &binary, &base, macos_host(), &missing_tool, &profile);
    assert_eq!(
        absent,
        format!(
            "wallet-provider start on macos is refused: the confinement tool {} is absent",
            missing_tool.display()
        )
    );

    let wrong_tool = refused(
        &home,
        &binary,
        &base,
        macos_host(),
        Path::new("/bin/echo"),
        &profile,
    );
    assert_eq!(
        wrong_tool,
        "wallet-provider start on macos is refused: the confinement tool /bin/echo is not /usr/bin/sandbox-exec, which is the one the stand-in runs"
    );

    let missing_bin = refused(&home, &missing_binary, &base, macos_host(), tool, &profile);
    assert_eq!(
        missing_bin,
        format!(
            "wallet-provider start is refused: the provider binary {} is not a file",
            missing_binary.display()
        )
    );

    let directory_bin = refused(&home, home.root(), &base, macos_host(), tool, &profile);
    assert_eq!(
        directory_bin,
        format!(
            "wallet-provider start is refused: the provider binary {} is not a file",
            home.root().display()
        )
    );

    assert!(
        !base.exists(),
        "a refused start creates no storage directory"
    );
    assert_no_child(&home);
    home.finish().expect("the passed home is removed");
}

/// The profile path the caller passes is the profile that runs. A restrictive
/// profile refuses `init`. A missing profile is refused. The normal profile
/// still starts.
///
/// Falsifier: F-shared-launch-wrong-profile launches the committed oracle
/// instead of the caller path, so the restrictive `init` creates the wallet
/// root. F-shared-launch-bare ignores the profile the same way.
#[test]
fn standin_provider_launch_uses_supplied_profile() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let committed = fs::read(committed_profile()).expect("the committed profile must be readable");
    let committed_text = String::from_utf8(committed.clone()).expect("the profile is UTF-8");
    let restrictive_text = committed_text.replacen(WRITE_GRANT, READ_GRANT, 1);
    assert_ne!(
        restrictive_text, committed_text,
        "setup: the restrictive profile must drop the wallet-root write"
    );

    let missing = home.root().join("missing-confine.sb");
    let missing_reason = refused(
        &home,
        binary,
        &home.root().join("missing-profile-base"),
        macos_host(),
        tool,
        &missing,
    );
    assert!(
        missing_reason.contains("is not a file"),
        "missing profile: {missing_reason}"
    );
    assert!(
        missing_reason.contains(&missing.display().to_string()),
        "missing profile names its path: {missing_reason}"
    );
    assert_no_child(&home);

    let restrictive_base = fresh_base(&home, "restrictive-base");
    let restrictive_wallet = wallet_dir(&restrictive_base);
    let restrictive = write_profile(&home, "restrictive.sb", restrictive_text.as_bytes());
    let stored = refused(
        &home,
        binary,
        &restrictive_base,
        macos_host(),
        tool,
        &restrictive,
    );
    assert!(
        stored.contains("storage_error"),
        "the refusal carries the init storage reason: {stored}"
    );
    assert!(
        stored.contains("wallet storage"),
        "the refusal names wallet storage: {stored}"
    );
    assert!(
        !restrictive_wallet.exists(),
        "a refused init leaves the wallet directory absent: {}",
        restrictive_wallet.display()
    );

    let normal_base = fresh_base(&home, "normal-base");
    let normal = write_profile(&home, "confine.sb", &committed);
    let started = start(&home, binary, &normal_base, macos_host(), tool, &normal)
        .expect("the normal caller profile still starts");
    assert_eq!(started.init["status"], "ok", "init: {}", started.init);
    assert!(
        wallet_dir(&normal_base).is_dir(),
        "the normal profile creates the wallet root"
    );
    started.shutdown().expect("shutdown exits 0");

    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("census after the children are reaped");
    assert!(
        census.contains("root checks PASS"),
        "census after reap: {census}"
    );
    home.finish().expect("the passed home is removed");
}

/// An unknown provider name is refused. It does not borrow the wallet layout.
///
/// Falsifier: F-shared-launch-unknown-name returns the wallet layout for every
/// other name, so this refusal disappears.
#[test]
fn standin_provider_launch_refuses_an_unknown_provider_name() {
    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let base = home.root().join("unknown-base");
    let profile = write_profile(&home, "confine.sb", b"(version 1)\n");
    let reason = match start_provider(
        &home,
        &profile,
        &base,
        "model-provider",
        macos_host(),
        tool,
        &profile,
    ) {
        Ok(_) => panic!("an unknown provider name is refused"),
        Err(reason) => reason,
    };
    assert_eq!(
        reason,
        "the stand-in serves only did-provider and wallet-provider, so model-provider has no storage root layout"
    );
    assert!(
        !base.exists(),
        "an unknown name creates no storage directory"
    );
    assert_no_child(&home);
    home.finish().expect("the passed home is removed");
}

/// A request that would pass the stdin limit is refused and is not written.
///
/// Falsifier: F-shared-launch-stdin removes the limit check. The oversized
/// request is then written and this refusal disappears.
#[test]
fn standin_provider_launch_refuses_stdin_past_its_limit() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile_bytes =
        fs::read(committed_profile()).expect("the committed profile must be readable");
    let profile = write_profile(&home, "confine.sb", &profile_bytes);
    let base = fresh_base(&home, "stdin-base");
    let mut started = start(&home, binary, &base, macos_host(), tool, &profile)
        .expect("the caller profile starts the provider");
    let pad = "a".repeat(STDIN_BYTE_LIMIT);
    let err = started
        .request(&json!({ "op": "status", "pad": pad }))
        .expect_err("a request past the stdin limit is refused");
    assert_eq!(err, "stdin exceeds its byte limit");
    let status = started
        .request(&json!({ "op": "status" }))
        .expect("the refused write leaves the provider able to answer");
    assert_eq!(status["status"], "ok", "status: {status}");
    started.shutdown().expect("shutdown exits 0");
    home.finish().expect("the passed home is removed");
}

/// A child that writes no line within the deadline is refused. The reason is
/// not the exit-deadline reason.
///
/// Falsifier: F-shared-launch-response-deadline removes the deadline check.
/// The wait then ends as a closed stream, and this reason disappears.
#[test]
fn standin_provider_launch_refuses_a_response_past_its_deadline() {
    let home = ThrowawayHome::new().expect("throwaway home");
    let mut child = home
        .start_with_input(
            Path::new("/bin/sleep"),
            &["2"],
            ChildInput::Bounded {
                limit: STDIN_BYTE_LIMIT,
            },
        )
        .expect("the sleep child starts");
    let err = child
        .read_line_within(Duration::from_millis(200))
        .expect_err("a silent child is refused at the response deadline");
    assert_eq!(err, "provider response exceeded its deadline");
    child.stop().expect("the sleep child is reaped");
    drop(child);
    home.finish().expect("the passed home is removed");
}

/// A child that does not exit within the deadline is refused. The reason is
/// not the response-deadline reason.
///
/// Falsifier: F-shared-launch-exit-deadline removes the deadline check. The
/// wait then returns the child's exit, and this reason disappears.
#[test]
fn standin_provider_launch_refuses_an_exit_past_its_deadline() {
    let home = ThrowawayHome::new().expect("throwaway home");
    let mut child = home
        .start_with_input(
            Path::new("/bin/sleep"),
            &["2"],
            ChildInput::Bounded {
                limit: STDIN_BYTE_LIMIT,
            },
        )
        .expect("the sleep child starts");
    let err = child
        .wait_for_exit_within(Duration::from_millis(200))
        .expect_err("a child that stays up is refused at the exit deadline");
    assert_eq!(err, "provider exit exceeded its deadline");
    child.stop().expect("the sleep child is reaped");
    drop(child);
    home.finish().expect("the passed home is removed");
}
