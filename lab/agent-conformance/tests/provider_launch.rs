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
/// Falsifier: drop the missing-primitive check, admit Linux or an unsupported
/// OS, drop the absent-tool check, drop the wrong-tool check, or drop the
/// binary-file check. Each of those leaves this test's matching reason false.
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

/// Request A waits past the deadline, then writes its success before reading
/// request B. A returns the deadline. The child is reaped, so B cannot read
/// A's line. Shutdown is the same refusal.
///
/// Falsifier: F-shared-launch-deadline-cleanup removes the deadline
/// settlement. B then receives A's success body.
#[test]
fn standin_provider_launch_refuses_the_next_request_after_a_response_deadline() {
    use std::os::unix::fs::PermissionsExt;

    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile = write_profile(&home, "fixture.sb", b"(version 1)\n(allow default)\n");
    let binary = home.root().join("late-provider");
    // `read -t` waits in this process. A separate sleep would survive the
    // shell and keep the process group up after the deadline.
    fs::write(
        &binary,
        "#!/bin/sh\n\
         IFS= read -r _init\n\
         printf '%s\\n' '{\"status\":\"ok\",\"data\":{\"storage_configured\":true}}'\n\
         IFS= read -r _request\n\
         read -t 6 _delay\n\
         printf '%s\\n' '{\"status\":\"ok\",\"data\":{\"answered\":\"A\"}}'\n\
         IFS= read -r _next\n\
         printf '%s\\n' '{\"status\":\"ok\",\"data\":{\"answered\":\"B\"}}'\n",
    )
    .expect("write the late-reply fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("make the fixture executable");
    let base = fresh_base(&home, "late-base");
    let mut started = start(&home, &binary, &base, macos_host(), tool, &profile)
        .expect("the fixture answers init");
    let first = started
        .request(&json!({ "op": "status", "which": "A" }))
        .expect_err("request A exceeds the response deadline");
    assert_eq!(first, "provider response exceeded its deadline");
    let second = started.request(&json!({ "op": "status", "which": "B" }));
    assert_eq!(
        second,
        Err("provider dialogue ended: provider response exceeded its deadline".to_string())
    );
    let shutdown = started.shutdown();
    assert_eq!(
        shutdown,
        Err("provider dialogue ended: provider response exceeded its deadline".to_string())
    );
    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("census after the deadline reaps the child");
    assert!(
        census.contains("root checks PASS"),
        "census after the deadline: {census}"
    );
    home.finish().expect("the passed home is removed");
}

/// Each malformed line is followed by A's valid reply. B must receive the
/// retained refusal, and the physical census must pass before shutdown.
#[test]
fn standin_provider_launch_refuses_the_next_request_after_a_framing_failure() {
    for (reply, expected) in [
        (
            "printf 'invalid\\n{\"status\":\"ok\",\"answered\":\"A\"}\\n'",
            "provider answered with invalid JSON: invalid",
        ),
        (
            "printf '\\377\\n{\"status\":\"ok\",\"answered\":\"A\"}\\n'",
            "provider response is not UTF-8",
        ),
    ] {
        assert_exchange_ends_dialogue(
            "",
            &format!("{reply}\nIFS= read -r _next\nIFS= read -r _hold\n"),
            expected,
        );
    }
}

/// A partial line at exit, closed stdin, and damaged stdout each retain their
/// own transport reason. Each failure settles the same child owner.
#[test]
fn standin_provider_launch_refuses_the_next_request_after_a_transport_failure() {
    assert_exchange_ends_dialogue(
        "",
        "printf '{\"status\":\"ok\"}'\nexit 7\n",
        "provider response stream ended",
    );
    assert_exchange_ends_dialogue("exec 0<&-\n", "", "could not write child stdin");
    assert_exchange_ends_dialogue(
        "",
        "for capture in \"$HOME\"/../stdout-*; do : > \"$capture\"; done\nIFS= read -r _hold\n",
        "could not inspect child stdout",
    );
}

fn assert_exchange_ends_dialogue(before_init_reply: &str, after_request: &str, expected: &str) {
    use std::os::unix::fs::PermissionsExt;

    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile = write_profile(&home, "fixture.sb", b"(version 1)\n(allow default)\n");
    let binary = home.root().join("broken-dialogue-provider");
    let dialogue = if before_init_reply.is_empty() {
        format!("IFS= read -r _request\n{after_request}")
    } else {
        // The fixture closed stdin before init's reply. Exec keeps the same
        // owned process alive until the failed write stops it.
        "exec /bin/sleep 60\n".to_string()
    };
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\n\
             IFS= read -r _init\n\
             {before_init_reply}\
             printf '%s\\n' '{{\"status\":\"ok\"}}'\n\
             {dialogue}"
        ),
    )
    .expect("write the failed-exchange fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("make the fixture executable");
    let base = fresh_base(&home, "broken-dialogue-base");
    let mut started = start(&home, &binary, &base, macos_host(), tool, &profile)
        .expect("the fixture answers init and stays alive");
    assert_eq!(
        started.request(&json!({ "op": "status", "which": "A" })),
        Err(expected.to_string()),
        "the first refusal keeps its own reason"
    );
    assert_eq!(
        started.request(&json!({ "op": "status", "which": "B" })),
        Err(format!("provider dialogue ended: {expected}")),
        "B cannot consume A's queued response"
    );
    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("census while the failed dialogue is still owned");
    assert!(census.contains("root checks PASS"), "census: {census}");
    assert_eq!(
        started.shutdown(),
        Err(format!("provider dialogue ended: {expected}"))
    );
    home.finish().expect("the passed home is removed");
}

/// A buffered init success from an exited child supplies no live owner.
/// Check both normal exit and the reported status-7 reproduction.
#[test]
fn standin_provider_launch_refuses_an_exited_child_after_init() {
    use std::os::unix::fs::PermissionsExt;

    let tool = require_confinement_tool();
    for status in [0, 7] {
        let home = ThrowawayHome::new().expect("throwaway home");
        let profile = write_profile(&home, "fixture.sb", b"(version 1)\n(allow default)\n");
        let binary = home.root().join("exiting-provider");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\n\
                 IFS= read -r _init\n\
                 printf '%s\\n' '{{\"status\":\"ok\"}}'\n\
                 exit {status}\n"
            ),
        )
        .expect("write the early-exit fixture");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("make the fixture executable");
        let base = fresh_base(&home, "early-exit-base");
        let result = start(&home, &binary, &base, macos_host(), tool, &profile);
        assert_eq!(
            result.err().expect("an exited child cannot be Started"),
            "wallet-provider start is refused: provider exited after init response"
        );
        let census = agent_conformance::census::cleanup(&home, closed_port())
            .expect("census after the early-exit refusal");
        assert!(census.contains("root checks PASS"), "census: {census}");
        home.finish().expect("the passed home is removed");
    }
}

/// Initialization applies the same framing rule and stops a child that sends
/// an invalid response. A partial final line remains a stream-ended refusal.
#[test]
fn standin_provider_launch_refuses_invalid_init_responses() {
    use std::os::unix::fs::PermissionsExt;

    let tool = require_confinement_tool();
    for (reply, expected) in [
        ("printf '\\377\\n'", "provider response is not UTF-8"),
        ("printf 'null\\n'", "init answered null"),
        (
            "printf '{\"status\":\"ok\"}'\nexit 7",
            "provider response stream ended",
        ),
    ] {
        let home = ThrowawayHome::new().expect("throwaway home");
        let profile = write_profile(&home, "fixture.sb", b"(version 1)\n(allow default)\n");
        let binary = home.root().join("invalid-init-provider");
        fs::write(
            &binary,
            format!("#!/bin/sh\nIFS= read -r _init\n{reply}\nIFS= read -r _hold\n"),
        )
        .expect("write the invalid-init fixture");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("make the fixture executable");
        let base = fresh_base(&home, "invalid-init-base");
        assert_eq!(
            start(&home, &binary, &base, macos_host(), tool, &profile)
                .err()
                .expect("invalid init is refused"),
            format!("wallet-provider start is refused: {expected}")
        );
        let census = agent_conformance::census::cleanup(&home, closed_port())
            .expect("census after the invalid-init refusal");
        assert!(census.contains("root checks PASS"), "census: {census}");
        home.finish().expect("the passed home is removed");
    }
}

/// Run the cwd change in an isolated test process through the existing harness,
/// so other tests keep their working directory. Reuse the parent's built binary.
#[test]
fn standin_provider_launch_resolves_relative_profile_once() {
    let marker = Path::new("relative-profile-binary");
    if !marker.is_file() {
        let binary = wallet_provider_binary();
        let isolated = ThrowawayHome::new().expect("isolated test home");
        fs::write(
            isolated.home().join(marker),
            binary.as_os_str().as_encoded_bytes(),
        )
        .expect("record the built binary for the isolated test");
        let output = isolated
            .launch(
                &std::env::current_exe().expect("test executable"),
                &[
                    "--exact",
                    "standin_provider_launch_resolves_relative_profile_once",
                    "--test-threads=1",
                    "--nocapture",
                ],
                Duration::from_secs(30),
            )
            .expect("the isolated relative-profile test completes");
        assert!(
            output.status.success(),
            "relative-profile test: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        isolated
            .finish()
            .expect("the isolated test home is removed");
        return;
    }

    let binary = PathBuf::from(fs::read_to_string(marker).expect("the built binary path"));
    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let normal = fs::read_to_string(committed_profile()).expect("the committed profile");
    let restrictive = normal.replacen(WRITE_GRANT, READ_GRANT, 1);
    assert_ne!(restrictive, normal, "setup: remove the wallet write grant");
    write_profile(&home, "selected.sb", restrictive.as_bytes());
    fs::write(home.home().join("selected.sb"), normal).expect("the permissive decoy");
    std::os::unix::fs::symlink(binary, home.root().join("provider"))
        .expect("relative binary in the caller directory");
    std::os::unix::fs::symlink("/usr/bin/false", home.home().join("provider"))
        .expect("binary decoy in the child's directory");
    let base = fresh_base(&home, "relative-profile-base");
    let previous = std::env::current_dir().expect("the original working directory");
    std::env::set_current_dir(home.root()).expect("use the caller's directory");
    let result = start(
        &home,
        Path::new("provider"),
        &base,
        macos_host(),
        tool,
        Path::new("selected.sb"),
    );
    std::env::set_current_dir(previous).expect("restore the working directory");
    let reason = result
        .err()
        .expect("the restrictive caller profile refuses init");
    assert!(reason.contains("storage_error"), "init refusal: {reason}");
    assert!(
        reason.contains("wallet storage"),
        "storage reason: {reason}"
    );
    assert!(!wallet_dir(&base).exists(), "the wallet root stays absent");
    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("census after the refused child is reaped");
    assert!(census.contains("root checks PASS"), "census: {census}");
    home.finish().expect("the passed home is removed");
}

fn storage_stays_home(base: &Path) -> String {
    format!(
        "wallet-provider start is refused: the storage root {} stays under this home",
        wallet_dir(base).display()
    )
}

fn home_name(home: &ThrowawayHome) -> String {
    home.root()
        .file_name()
        .expect("home name")
        .to_string_lossy()
        .into_owned()
}

/// Removes a path this test created, or a path a broken launch created.
struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn normal_profile(home: &ThrowawayHome) -> PathBuf {
    let bytes = fs::read(committed_profile()).expect("the committed profile must be readable");
    write_profile(home, "confine.sb", &bytes)
}

/// The first base is an absent sibling of the home. The normal profile would
/// allow wallet init there. The seam refuses before it creates that sibling
/// and before it starts a child.
///
/// Falsifier: F-shared-launch-unowned deletes the `directories_only` call.
/// This test, the parent-segment test and the symlink test then fail.
#[test]
fn standin_provider_launch_refuses_storage_outside_its_home() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile = normal_profile(&home);
    let sibling = home
        .root()
        .parent()
        .expect("lane target")
        .join(format!("outside-base-{}", home_name(&home)));
    let _cleanup = RemoveDir(sibling.clone());
    assert!(
        !sibling.exists(),
        "the outside base starts absent: {}",
        sibling.display()
    );

    let reason = refused(&home, binary, &sibling, macos_host(), tool, &profile);
    assert_eq!(reason, storage_stays_home(&sibling));
    assert!(
        !sibling.exists(),
        "an outside base creates no directory: {}",
        sibling.display()
    );
    assert_no_child(&home);
    home.finish().expect("the passed home is removed");
}

/// A base whose lexical path contains `..` leaves the home. The seam refuses
/// before `create_dir_all` follows that segment and before a child starts.
///
/// Falsifier: F-shared-launch-dotdot deletes the non-normal component refusal
/// in `directories_only`. The launch then creates the escaped parent and the
/// ownership assertion fails. F-shared-launch-unowned deletes the call and
/// this test fails with the other two.
#[test]
fn standin_provider_launch_refuses_storage_with_a_parent_segment() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile = normal_profile(&home);
    let escaped = home
        .root()
        .parent()
        .expect("lane target")
        .join(format!("outside-dotdot-{}", home_name(&home)));
    let _cleanup = RemoveDir(escaped.clone());
    let base = home
        .root()
        .join(format!("nested/../../outside-dotdot-{}", home_name(&home)));
    assert!(
        !escaped.exists(),
        "the escaped directory starts absent: {}",
        escaped.display()
    );

    let reason = refused(&home, binary, &base, macos_host(), tool, &profile);
    assert_eq!(reason, storage_stays_home(&base));
    assert!(
        reason.contains(".."),
        "the refusal keeps the parent segment: {reason}"
    );
    assert!(
        !escaped.exists(),
        "a parent segment creates no directory: {}",
        escaped.display()
    );
    assert!(
        !home.root().join("nested").exists(),
        "a parent segment creates no intermediate directory"
    );
    assert_no_child(&home);
    home.finish().expect("the passed home is removed");
}

/// A base that is a symlink to a directory outside the home is refused before
/// the seam creates children through that link and before a child starts.
///
/// Falsifier: F-shared-launch-unowned deletes the `directories_only` call.
/// The launch then creates `ElastOS` through the link and the ownership
/// assertion fails.
#[test]
fn standin_provider_launch_refuses_storage_through_a_symlink() {
    let tool = require_confinement_tool();
    let binary = wallet_provider_binary();
    let home = ThrowawayHome::new().expect("throwaway home");
    let profile = normal_profile(&home);
    let outside = home
        .root()
        .parent()
        .expect("lane target")
        .join(format!("outside-link-{}", home_name(&home)));
    let _cleanup = RemoveDir(outside.clone());
    fs::create_dir(&outside).expect("the symlink target must exist");
    let link = home.root().join("storage-link");
    std::os::unix::fs::symlink(&outside, &link).expect("the base symlink");
    assert!(
        !outside.join("ElastOS").exists(),
        "the link target starts without storage"
    );

    let reason = refused(&home, binary, &link, macos_host(), tool, &profile);
    assert_eq!(reason, storage_stays_home(&link));
    assert!(
        !outside.join("ElastOS").exists(),
        "a symlink base creates no directory in {}",
        outside.display()
    );
    assert_no_child(&home);
    home.finish().expect("the passed home is removed");
}

/// The borrowed root keeps its original identity before any storage access.
/// Both a symlink and a different directory at the same path are refused.
#[test]
fn standin_provider_launch_refuses_a_replaced_home_root() {
    let tool = require_confinement_tool();
    let external = ThrowawayHome::new().expect("external launch inputs");
    let profile = normal_profile(&external);
    for symlink in [true, false] {
        let home = ThrowawayHome::new().expect("throwaway home");
        let saved_root = external.root().join("saved-home");
        let unrelated = external.root().join("unrelated");
        fs::create_dir(&unrelated).expect("the unrelated directory");
        fs::write(unrelated.join("sentinel"), b"unchanged").expect("unrelated contents");
        fs::rename(home.root(), &saved_root).expect("retain the owned root");
        if symlink {
            std::os::unix::fs::symlink(&unrelated, home.root()).expect("replace the root");
        } else {
            fs::rename(&unrelated, home.root()).expect("replace the root directory");
        }
        let reason = refused(
            &home,
            Path::new("/usr/bin/false"),
            &home.root().join("base"),
            macos_host(),
            tool,
            &profile,
        );
        if symlink {
            fs::remove_file(home.root()).expect("remove the replacement link");
        } else {
            fs::rename(home.root(), &unrelated).expect("return the unrelated directory");
        }
        fs::rename(&saved_root, home.root()).expect("restore the owned root");
        assert_eq!(
            reason,
            "wallet-provider start is refused: throwaway root is no longer the fresh directory"
        );
        let entries: Vec<_> = fs::read_dir(&unrelated)
            .expect("inspect the unrelated directory")
            .map(|entry| entry.expect("unrelated entry").file_name())
            .collect();
        assert_eq!(entries, ["sentinel"], "storage leaves the target unchanged");
        assert_eq!(
            fs::read(unrelated.join("sentinel")).expect("sentinel bytes"),
            b"unchanged"
        );
        assert_no_child(&home);
        home.finish().expect("the restored home is removed");
        fs::remove_dir_all(unrelated).expect("remove the unchanged fixture directory");
    }
    external.finish().expect("external inputs are removed");
}

/// Exercise both response failures with a child and descendant that stay alive
/// after the reply. Cleanup must finish while the temp guard still refuses.
fn refusal_cleans_replaced_temp(shutdown: bool, invalid_json: bool, request: bool) {
    use std::os::unix::fs::PermissionsExt;

    let tool = require_confinement_tool();
    let home = ThrowawayHome::new().expect("throwaway home");
    let observer = ThrowawayHome::new().expect("independent process observer");
    let profile = write_profile(&home, "fixture.sb", b"(version 1)\n(allow default)\n");
    let binary = home.root().join("provider-fixture");
    let response = if invalid_json {
        "invalid-response".to_owned()
    } else {
        json!({ "status": "error", "message": "fixture refuses" }).to_string()
    };
    let first_reply = if shutdown || request {
        "printf '%s\\n' '{\"status\":\"ok\"}'\nIFS= read -r request\n"
    } else {
        ""
    };
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\n\
             trap '' TERM\n\
             /bin/sleep 60 &\n\
             printf '%s\\n' \"$$\" > \"$HOME/provider-pgid\"\n\
             IFS= read -r request\n\
             {first_reply}\
             /bin/mv \"$TMPDIR\" \"$TMPDIR-saved\"\n\
             /bin/ln -s \"$TMPDIR-saved\" \"$TMPDIR\"\n\
             printf '%s\\n' '{response}'\n\
             wait\n"
        ),
    )
    .expect("write the provider fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
        .expect("make the fixture executable");
    let base = home.root().join("base");
    let result = start(&home, &binary, &base, macos_host(), tool, &profile);
    let reason = if request {
        let mut started = result.expect("the fixture answers init ok");
        let reason = started
            .request(&json!({ "op": "status" }))
            .expect_err("the request response is refused");
        assert_eq!(
            started.request(&json!({ "op": "status" })),
            Err(format!("provider dialogue ended: {reason}"))
        );
        assert_eq!(
            started.shutdown(),
            Err(format!("provider dialogue ended: {reason}"))
        );
        reason
    } else if shutdown {
        result
            .expect("the fixture answers init ok")
            .shutdown()
            .expect_err("the shutdown response is refused")
    } else {
        result.err().expect("the init response is refused")
    };
    let pgid = fs::read_to_string(home.home().join("provider-pgid"))
        .expect("the provider recorded its process group")
        .trim()
        .parse()
        .expect("the process group is numeric");
    let guard = home.guard(home.home(), home.data());
    let alive = observer
        .group_is_alive(pgid)
        .expect("inspect the group before restoring temp");
    if alive {
        // Keep a failing regression from leaving the fixture running.
        observer
            .launch(
                Path::new("/bin/kill"),
                &["-KILL", &format!("-{pgid}")],
                Duration::from_secs(1),
            )
            .expect("stop the failed fixture");
    }
    fs::remove_file(home.temp()).expect("remove the temp symlink");
    fs::rename(home.root().join("tmp-saved"), home.temp()).expect("restore temp");
    assert_eq!(
        guard,
        Err("temp directory must use directories without symlinks")
    );
    assert!(
        !alive,
        "refusal must reap the provider and drain its group before returning"
    );
    let response_reason = if invalid_json {
        format!("provider answered with invalid JSON: {response}")
    } else if shutdown {
        format!("shutdown answered {response}")
    } else {
        format!("init answered {response}")
    };
    let prefix = if shutdown || request {
        ""
    } else {
        "wallet-provider start is refused: "
    };
    assert_eq!(
        reason,
        format!("{prefix}{response_reason}; cleanup failed: temp directory must use directories without symlinks")
    );
    let census = agent_conformance::census::cleanup(&home, closed_port())
        .expect("physical cleanup after refusal");
    assert!(census.contains("root checks PASS"), "census: {census}");
    observer.finish().expect("remove the observer");
    let root = home.root().to_path_buf();
    assert_eq!(
        home.finish(),
        Err("keep the root after an unstopped child or failed stop")
    );
    fs::remove_dir_all(root).expect("remove the verified retained test root");
}

#[test]
fn standin_provider_launch_refusal_cleans_a_replaced_temp() {
    for invalid_json in [false, true] {
        refusal_cleans_replaced_temp(false, invalid_json, false);
    }
}

#[test]
fn standin_provider_shutdown_refusal_cleans_a_replaced_temp() {
    for invalid_json in [false, true] {
        refusal_cleans_replaced_temp(true, invalid_json, false);
    }
}

#[test]
fn standin_provider_request_refusal_cleans_a_replaced_temp() {
    refusal_cleans_replaced_temp(false, true, true);
}

/// A failed timeout cleanup leaves the same owner able to retry through either
/// explicit stop or Drop after the Home's directory guard is restored.
#[test]
fn standin_provider_exit_cleanup_failure_keeps_ownership() {
    for explicit_stop in [true, false] {
        let home = ThrowawayHome::new().expect("throwaway home");
        let mut child = home
            .start(Path::new("/bin/sleep"), &["60"])
            .expect("the long-running child starts");
        let pgid = child.pgid();
        let saved_temp = home.root().join("saved-tmp");
        fs::rename(home.temp(), &saved_temp).expect("retain the original temp directory");
        std::os::unix::fs::symlink(&saved_temp, home.temp()).expect("block the kill helper");
        let result = child.wait_for_exit_within(Duration::ZERO);
        fs::remove_file(home.temp()).expect("remove the temp symlink");
        fs::rename(saved_temp, home.temp()).expect("restore the temp directory");
        assert_eq!(
            result.unwrap_err(),
            "managed process group remains after SIGKILL"
        );
        assert!(child
            .is_alive()
            .expect("inspect the child after failed cleanup"));
        if explicit_stop {
            child
                .stop()
                .expect("stop retries cleanup after the guard is restored");
            assert!(!child.is_alive().expect("the stopped child is reaped"));
        }
        drop(child);
        assert!(!home.group_is_alive(pgid).expect("the owned group is gone"));
        let census = agent_conformance::census::cleanup(&home, closed_port())
            .expect("census after cleanup retries");
        assert!(census.contains("root checks PASS"), "census: {census}");
        if explicit_stop {
            home.finish().expect("the passed home is removed");
        } else {
            let root = home.root().to_path_buf();
            assert_eq!(
                home.finish(),
                Err("keep the root after an unstopped child or failed stop")
            );
            // The test has verified Drop's retention rule and the empty group.
            fs::remove_dir_all(root).expect("remove the verified retained test root");
        }
    }
}
